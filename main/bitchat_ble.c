#include "bitchat_ble.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_nimble_hci.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gatt.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "bitchat_time.h"
#include "bitle_ota.h"
#include "noise_handshake.h"
#include "packet_codec.h"

#define BITLE_DEVICE_NAME "Bitle Relay"
#define BITLE_BLE_MAX_CONNECTIONS CONFIG_BT_NIMBLE_MAX_CONNECTIONS

static const char *TAG = "BLE_INIT";

static uint16_t s_tx_val_handle;
static bool s_host_synced;
static uint8_t s_own_addr_type;

typedef struct {
    bool in_use;
    bool subscribed;
    uint16_t conn_handle;
    uint64_t connected_at_ms;
} ble_conn_state_t;

static ble_conn_state_t s_connections[BITLE_BLE_MAX_CONNECTIONS];
static int gap_event_cb(struct ble_gap_event *event, void *arg);

/* BitChat mainnet service F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C — the app
 * scans exclusively for this UUID; anything else is invisible to it. */
static const ble_uuid128_t s_service_uuid =
    BLE_UUID128_INIT(0x5c, 0x4b, 0x3a, 0x2c, 0x1d, 0x8e, 0x3f, 0x9b,
                     0x5a, 0x4c, 0x9e, 0x4a, 0x2d, 0x5e, 0x7b, 0xf4);
/* BitChat characteristic A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D */
static const ble_uuid128_t s_txrx_uuid =
    BLE_UUID128_INIT(0x5d, 0x4c, 0x3b, 0x2a, 0x1f, 0x0e, 0x9d, 0x8c,
                     0x5b, 0x4a, 0xf6, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1);

static ble_conn_state_t *find_conn(uint16_t conn_handle)
{
    for (size_t i = 0; i < BITLE_BLE_MAX_CONNECTIONS; ++i) {
        if (s_connections[i].in_use && s_connections[i].conn_handle == conn_handle) {
            return &s_connections[i];
        }
    }
    return NULL;
}

static ble_conn_state_t *alloc_conn(uint16_t conn_handle)
{
    ble_conn_state_t *existing = find_conn(conn_handle);
    if (existing) {
        return existing;
    }
    for (size_t i = 0; i < BITLE_BLE_MAX_CONNECTIONS; ++i) {
        if (!s_connections[i].in_use) {
            memset(&s_connections[i], 0, sizeof(s_connections[i]));
            s_connections[i].in_use = true;
            s_connections[i].conn_handle = conn_handle;
            return &s_connections[i];
        }
    }
    return NULL;
}

static void drop_conn(uint16_t conn_handle)
{
    ble_conn_state_t *state = find_conn(conn_handle);
    if (!state) {
        return;
    }
    memset(state, 0, sizeof(*state));
}

static void dispatch_packet(uint16_t conn_handle, const bitchat_packet_t *packet);

/* --- Fragment reassembly ---------------------------------------------------
 * Phones fragment packets that exceed the link write budget (a 256-padded
 * packet does not fit ATT_MTU-3 = 253 at MTU 256), so directly connected
 * peers routinely fragment handshakes and DMs. Fragment payload layout:
 * [8B fragment ID][2B index BE][2B total BE][1B original type][chunk].
 * Reassembled bytes are the original packet's full encoding. */

#define FRAG_SLOTS      2
#define FRAG_MAX_PARTS  4
#define FRAG_PART_MAX   250
#define FRAG_TIMEOUT_MS 15000ULL

typedef struct {
    bool in_use;
    uint64_t frag_id;
    uint8_t sender[8];
    uint16_t total;
    uint32_t have_mask;
    uint64_t started_ms;
    uint16_t part_len[FRAG_MAX_PARTS];
    uint8_t part[FRAG_MAX_PARTS][FRAG_PART_MAX];
} frag_slot_t;

static frag_slot_t s_frag_slots[FRAG_SLOTS];

static void handle_fragment(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    const uint8_t *p = packet->payload;
    if (!p || packet->payload_len < 13) {
        return;
    }
    uint64_t frag_id = 0;
    for (int i = 0; i < 8; ++i) {
        frag_id = (frag_id << 8) | p[i];
    }
    uint16_t index = ((uint16_t)p[8] << 8) | p[9];
    uint16_t total = ((uint16_t)p[10] << 8) | p[11];
    uint16_t chunk_len = packet->payload_len - 13;
    if (total == 0 || index >= total || chunk_len == 0) {
        return;
    }
    if (total > FRAG_MAX_PARTS || chunk_len > FRAG_PART_MAX) {
        ESP_LOGI(TAG, "Fragment exceeds local limits (total=%u len=%u); relay-only", total, chunk_len);
        return;
    }

    uint64_t now = esp_timer_get_time() / 1000ULL;
    frag_slot_t *slot = NULL;
    frag_slot_t *free_slot = NULL;
    frag_slot_t *oldest = &s_frag_slots[0];
    for (size_t i = 0; i < FRAG_SLOTS; ++i) {
        frag_slot_t *s = &s_frag_slots[i];
        if (s->in_use && now - s->started_ms > FRAG_TIMEOUT_MS) {
            s->in_use = false;
        }
        if (s->in_use && s->frag_id == frag_id &&
            memcmp(s->sender, packet->sender_id, sizeof(s->sender)) == 0) {
            slot = s;
        } else if (!s->in_use && !free_slot) {
            free_slot = s;
        }
        if (s->started_ms < oldest->started_ms) {
            oldest = s;
        }
    }
    if (!slot) {
        slot = free_slot ? free_slot : oldest;
        memset(slot, 0, sizeof(*slot));
        slot->in_use = true;
        slot->frag_id = frag_id;
        memcpy(slot->sender, packet->sender_id, sizeof(slot->sender));
        slot->total = total;
        slot->started_ms = now;
    }
    if (slot->total != total) {
        return;
    }
    slot->part_len[index] = chunk_len;
    memcpy(slot->part[index], p + 13, chunk_len);
    slot->have_mask |= 1u << index;

    uint32_t want_mask = (1u << total) - 1;
    if ((slot->have_mask & want_mask) != want_mask) {
        return;
    }

    static uint8_t reassembled[FRAG_MAX_PARTS * FRAG_PART_MAX];
    size_t reassembled_len = 0;
    for (uint16_t i = 0; i < total; ++i) {
        memcpy(reassembled + reassembled_len, slot->part[i], slot->part_len[i]);
        reassembled_len += slot->part_len[i];
    }
    slot->in_use = false;

    bitchat_packet_t inner;
    if (!bitchat_packet_decode(reassembled, reassembled_len, &inner)) {
        ESP_LOGW(TAG, "Failed to decode reassembled packet (%u bytes)", (unsigned)reassembled_len);
        return;
    }
    ESP_LOGI(TAG, "Reassembled packet type=0x%02X len=%u from %u fragments",
             inner.type, inner.payload_len, total);
    if (inner.type != BITCHAT_MSG_FRAGMENT) {
        dispatch_packet(conn_handle, &inner);
    }
    bitchat_packet_free(&inner);
}

static bool is_broadcast_recipient(const bitchat_packet_t *packet)
{
    if (!packet->has_recipient) {
        return true;
    }
    for (size_t i = 0; i < sizeof(packet->recipient_id); ++i) {
        if (packet->recipient_id[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

static bool is_local_recipient(const bitchat_packet_t *packet)
{
    return packet->has_recipient &&
           memcmp(packet->recipient_id, noise_get_local_peer_id(), sizeof(packet->recipient_id)) == 0;
}

static void dispatch_packet(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    ESP_LOGI(TAG, "RX conn=%u type=0x%02X len=%u ttl=%u from=%02X%02X%02X%02X to=%s%s",
             conn_handle, packet->type, packet->payload_len, packet->ttl,
             packet->sender_id[0], packet->sender_id[1], packet->sender_id[2], packet->sender_id[3],
             is_broadcast_recipient(packet) ? "bcast" : (is_local_recipient(packet) ? "us" : "other"),
             packet->is_compressed ? " (compressed)" : "");

    /* Every packet a phone sends carries its wall clock in the header; use
     * them all so a solo iPhone's first transmission of any type syncs us. */
    bitchat_time_consider_peer(packet->timestamp_ms);

    if (packet->is_compressed) {
        /* No zlib inflate on this target; the relay path still forwards the
         * raw bytes, we just cannot act on the payload locally. */
        return;
    }
    if (!is_broadcast_recipient(packet) && !is_local_recipient(packet)) {
        return; /* directed at another peer; the relay layer forwards it */
    }

    switch (packet->type) {
    case BITCHAT_MSG_ANNOUNCE:
        noise_handle_announce(conn_handle, packet);
        break;
    case BITCHAT_MSG_NOISE_HANDSHAKE:
        noise_handle_handshake(conn_handle, packet);
        break;
    case BITCHAT_MSG_NOISE_ENCRYPTED:
        noise_handle_encrypted(conn_handle, packet);
        break;
    case BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE:
        noise_handle_identity_announce(conn_handle, packet);
        break;
    case BITCHAT_MSG_MESSAGE:
        noise_handle_public_message(conn_handle, packet);
        break;
    case BITCHAT_MSG_FRAGMENT:
        handle_fragment(conn_handle, packet);
        break;
    case BITLE_MSG_OTA_MANIFEST:
    case BITLE_MSG_OTA_REQ:
    case BITLE_MSG_OTA_CHUNK:
    case BITLE_MSG_OTA_STATUS:
        bitle_ota_handle_packet(conn_handle, packet);
        break;
    case BITCHAT_MSG_LEAVE:
    case BITCHAT_MSG_REQUEST_SYNC:
        /* Nothing to do locally; requestSync is link-local. These were
         * VERSION_HELLO/ACK in the old protocol and must never be answered. */
        break;
    default:
        ESP_LOGD(TAG, "Ignoring packet type 0x%02X locally", packet->type);
        break;
    }
}

/* --- Mesh relay -----------------------------------------------------------
 * Forwards packets between connected centrals: TTL-decremented, deduplicated
 * raw re-broadcast of everything not addressed to (or sent by) this node. */

#define RELAY_CACHE_SIZE 64

static uint64_t s_relay_seen[RELAY_CACHE_SIZE];
static size_t s_relay_seen_next;

static uint64_t relay_fingerprint(const uint8_t *data, size_t len)
{
    /* FNV-1a over the packet bytes, skipping the TTL byte (offset 2), which
     * changes at every hop and must not defeat deduplication. */
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) {
        if (i == 2) {
            continue;
        }
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool relay_seen_before(uint64_t fingerprint)
{
    for (size_t i = 0; i < RELAY_CACHE_SIZE; ++i) {
        if (s_relay_seen[i] == fingerprint) {
            return true;
        }
    }
    s_relay_seen[s_relay_seen_next] = fingerprint;
    s_relay_seen_next = (s_relay_seen_next + 1) % RELAY_CACHE_SIZE;
    return false;
}

static void relay_packet(uint16_t src_conn, uint8_t *buffer, uint16_t len, const bitchat_packet_t *packet)
{
    if (packet->ttl <= 1) {
        return;
    }
    if (memcmp(packet->sender_id, noise_get_local_peer_id(), sizeof(packet->sender_id)) == 0) {
        return; /* our own packet echoed back */
    }
    if (packet->type == BITCHAT_MSG_REQUEST_SYNC) {
        return; /* link-local by protocol */
    }
    if (is_local_recipient(packet)) {
        return; /* addressed to us; nothing to forward */
    }
    if (!packet->has_recipient && packet->type == BITCHAT_MSG_NOISE_HANDSHAKE) {
        return; /* undirected handshakes are link-local */
    }

    uint64_t fingerprint = relay_fingerprint(buffer, len);
    if (relay_seen_before(fingerprint)) {
        return;
    }

    buffer[2] = packet->ttl - 1;

    int forwarded = 0;
    for (size_t i = 0; i < BITLE_BLE_MAX_CONNECTIONS; ++i) {
        ble_conn_state_t *state = &s_connections[i];
        if (!state->in_use || !state->subscribed || state->conn_handle == src_conn) {
            continue;
        }
        struct os_mbuf *om = ble_hs_mbuf_from_flat(buffer, len);
        if (!om) {
            ESP_LOGW(TAG, "Relay alloc failed conn=%u", state->conn_handle);
            break;
        }
        int rc = ble_gattc_notify_custom(state->conn_handle, s_tx_val_handle, om);
        if (rc != 0) {
            ESP_LOGW(TAG, "Relay notify failed conn=%u rc=%d", state->conn_handle, rc);
        } else {
            forwarded++;
        }
    }
    if (forwarded > 0) {
        ESP_LOGI(TAG, "Relayed type=0x%02X ttl=%u to %d conn(s)", packet->type, buffer[2], forwarded);
    }
}

static int gatt_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)attr_handle;
    (void)arg;
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t pkt_len = OS_MBUF_PKTLEN(ctxt->om);
    if (pkt_len == 0 || pkt_len > BITCHAT_BLE_MAX_PACKET_SIZE) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    uint8_t buffer[BITCHAT_BLE_MAX_PACKET_SIZE];
    uint16_t copied = 0;
    int rc = ble_hs_mbuf_to_flat(ctxt->om, buffer, sizeof(buffer), &copied);
    if (rc != 0 || copied == 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    bitchat_packet_t packet;
    if (!bitchat_packet_decode(buffer, copied, &packet)) {
        ESP_LOGW(TAG, "Failed to decode inbound packet len=%u", copied);
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    dispatch_packet(conn_handle, &packet);
    relay_packet(conn_handle, buffer, copied, &packet);
    bitchat_packet_free(&packet);
    return 0;
}

static const struct ble_gatt_svc_def s_gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s_service_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = &s_txrx_uuid.u,
                .access_cb = gatt_access_cb,
                .val_handle = &s_tx_val_handle,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP |
                         BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_INDICATE,
            },
            {0},
        },
    },
    {0},
};

static void start_advertising(void)
{
    /* flags(3) + name(13) + uuid128(18) exceeds the 31-byte legacy advertising
     * payload, so the service UUID goes in the advertisement (clients scan by
     * it) and the name in the scan response. */
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = (ble_uuid128_t *)&s_service_uuid;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed rc=%d", rc);
        return;
    }

    struct ble_hs_adv_fields rsp_fields;
    memset(&rsp_fields, 0, sizeof(rsp_fields));
    rsp_fields.name = (const uint8_t *)BITLE_DEVICE_NAME;
    rsp_fields.name_len = (uint8_t)strlen(BITLE_DEVICE_NAME);
    rsp_fields.name_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_rsp_set_fields failed rc=%d", rc);
        return;
    }

    struct ble_gap_adv_params params;
    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    params.itvl_min = 0x0030;
    params.itvl_max = 0x0060;

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed rc=%d", rc);
    }
}

static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            uint16_t conn = event->connect.conn_handle;
            ble_conn_state_t *state = alloc_conn(conn);
            if (!state) {
                ESP_LOGW(TAG, "No conn slots left for handle=%u", conn);
                ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
            } else {
                state->connected_at_ms = esp_timer_get_time() / 1000ULL;
                ESP_LOGI(TAG, "Connected conn=%u", conn);
            }
        } else {
            ESP_LOGW(TAG, "Connect failed status=%d", event->connect.status);
            start_advertising();
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "Disconnected conn=%u reason=%d",
                 event->disconnect.conn.conn_handle, event->disconnect.reason);
        noise_reset_connection(event->disconnect.conn.conn_handle);
        drop_conn(event->disconnect.conn.conn_handle);
        start_advertising();
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE: {
        ble_conn_state_t *state = find_conn(event->subscribe.conn_handle);
        bool was_subscribed = state && state->subscribed;
        if (state) {
            state->subscribed = event->subscribe.cur_notify != 0 ||
                                event->subscribe.cur_indicate != 0;
        }
        ESP_LOGI(TAG, "Subscribe conn=%u notify=%d indicate=%d",
                 event->subscribe.conn_handle,
                 event->subscribe.cur_notify,
                 event->subscribe.cur_indicate);
        if (state && state->subscribed && !was_subscribed) {
            noise_notify_subscribed(event->subscribe.conn_handle);
        }
        return 0;
    }

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "MTU updated conn=%u mtu=%u",
                 event->mtu.conn_handle, event->mtu.value);
        return 0;

    default:
        return 0;
    }
}

static void on_sync(void)
{
    int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed rc=%d", rc);
        return;
    }

    uint8_t addr[6] = {0};
    rc = ble_hs_id_copy_addr(s_own_addr_type, addr, NULL);
    if (rc == 0) {
        ESP_LOGI(TAG, "Bluetooth MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    }

    s_host_synced = true;
    start_advertising();
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "NimBLE host reset reason=%d", reason);
}

static void nimble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
    vTaskDelete(NULL);
}

esp_err_t bitchat_ble_init(void)
{
    memset(s_connections, 0, sizeof(s_connections));

    int rc = nimble_port_init();
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "nimble_port_init failed rc=%d", rc);
        return ESP_FAIL;
    }

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.gatts_register_cb = NULL;
    ble_hs_cfg.store_status_cb = NULL;

    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_gap_device_name_set(BITLE_DEVICE_NAME);

    rc = ble_gatts_count_cfg(s_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_count_cfg failed rc=%d", rc);
        return ESP_FAIL;
    }
    rc = ble_gatts_add_svcs(s_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_add_svcs failed rc=%d", rc);
        return ESP_FAIL;
    }

    rc = ble_gap_adv_stop();
    if (rc != 0 && rc != BLE_HS_EALREADY && rc != BLE_HS_EINVAL) {
        ESP_LOGW(TAG, "ble_gap_adv_stop rc=%d", rc);
    }

    return ESP_OK;
}

esp_err_t bitchat_ble_start(void)
{
    nimble_port_freertos_init(nimble_host_task);
    return ESP_OK;
}

#define BITLE_SUBSCRIBE_TIMEOUT_MS 30000ULL

void bitchat_ble_poll(void)
{
    /* Watchdog: a central that connects but never enables notifications
     * leaves us mute on that link (seen with Android's stale GATT cache).
     * Disconnect it so it reconnects and redoes discovery + subscription. */
    uint64_t now = esp_timer_get_time() / 1000ULL;
    for (size_t i = 0; i < BITLE_BLE_MAX_CONNECTIONS; ++i) {
        ble_conn_state_t *state = &s_connections[i];
        if (!state->in_use || state->subscribed || !state->connected_at_ms) {
            continue;
        }
        if (now - state->connected_at_ms > BITLE_SUBSCRIBE_TIMEOUT_MS) {
            ESP_LOGW(TAG, "conn=%u never subscribed; disconnecting to force rediscovery", state->conn_handle);
            state->connected_at_ms = now; /* avoid repeat terminates while it closes */
            ble_gap_terminate(state->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
    }
}

bool bitchat_ble_conn_subscribed(uint16_t conn_handle)
{
    ble_conn_state_t *state = find_conn(conn_handle);
    return state && state->subscribed;
}

esp_err_t bitchat_ble_send(uint16_t conn_handle, const uint8_t *data, size_t len)
{
    if (!data || len == 0 || len > BITCHAT_BLE_MAX_PACKET_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_host_synced) {
        return ESP_ERR_INVALID_STATE;
    }

    ble_conn_state_t *state = find_conn(conn_handle);
    if (!state || !state->subscribed) {
        return ESP_ERR_INVALID_STATE;
    }

    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, (uint16_t)len);
    if (!om) {
        return ESP_ERR_NO_MEM;
    }

    int rc = ble_gattc_notify_custom(conn_handle, s_tx_val_handle, om);
    if (rc != 0) {
        ESP_LOGW(TAG, "notify failed conn=%u rc=%d", conn_handle, rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t bitchat_ble_send_with_ack(uint16_t conn_handle, const uint8_t *data, size_t len)
{
    if (!data || len == 0 || len > BITCHAT_BLE_MAX_PACKET_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_host_synced) {
        return ESP_ERR_INVALID_STATE;
    }

    ble_conn_state_t *state = find_conn(conn_handle);
    if (!state || !state->subscribed) {
        return ESP_ERR_INVALID_STATE;
    }

    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, (uint16_t)len);
    if (!om) {
        return ESP_ERR_NO_MEM;
    }

    int rc = ble_gatts_indicate_custom(conn_handle, s_tx_val_handle, om);
    if (rc != 0) {
        ESP_LOGW(TAG, "indicate failed conn=%u rc=%d", conn_handle, rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}
