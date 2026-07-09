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
    bool is_central;              /* we dialed this link (peer is another Bitle) */
    uint16_t conn_handle;
    uint16_t remote_val_handle;   /* peer's TX/RX characteristic (central links) */
    uint16_t svc_end_handle;
    ble_addr_t peer_addr;
    uint64_t connected_at_ms;
} ble_conn_state_t;

static ble_conn_state_t s_connections[BITLE_BLE_MAX_CONNECTIONS];
static int gap_event_cb(struct ble_gap_event *event, void *arg);
static void start_advertising(void);
static void central_start_discovery(uint16_t conn_handle);

/* Keep room for phones: at most this many outbound bitle-to-bitle links,
 * and never dial unless at least two slots stay free for inbound centrals. */
#define BITLE_CENTRAL_MAX_LINKS   2
#define BITLE_CENTRAL_RESERVE     2
#define BITLE_SCAN_INTERVAL_MS    60000ULL
#define BITLE_SCAN_DURATION_MS    5000
#define BITLE_DENY_TTL_MS         120000ULL

typedef struct {
    bool in_use;
    ble_addr_t addr;
    uint64_t until_ms;
} deny_entry_t;

static deny_entry_t s_deny[4];

static size_t count_connections(bool centrals_only)
{
    size_t n = 0;
    for (size_t i = 0; i < BITLE_BLE_MAX_CONNECTIONS; ++i) {
        if (s_connections[i].in_use && (!centrals_only || s_connections[i].is_central)) {
            n++;
        }
    }
    return n;
}

static bool addr_denied(const ble_addr_t *addr, uint64_t now)
{
    for (size_t i = 0; i < sizeof(s_deny) / sizeof(s_deny[0]); ++i) {
        if (s_deny[i].in_use && now < s_deny[i].until_ms &&
            ble_addr_cmp(&s_deny[i].addr, addr) == 0) {
            return true;
        }
    }
    return false;
}

static void deny_addr(const ble_addr_t *addr, uint64_t now)
{
    deny_entry_t *slot = &s_deny[0];
    for (size_t i = 0; i < sizeof(s_deny) / sizeof(s_deny[0]); ++i) {
        if (!s_deny[i].in_use || now >= s_deny[i].until_ms) {
            slot = &s_deny[i];
            break;
        }
        if (s_deny[i].until_ms < slot->until_ms) {
            slot = &s_deny[i];
        }
    }
    slot->in_use = true;
    slot->addr = *addr;
    slot->until_ms = now + BITLE_DENY_TTL_MS;
}

static bool already_linked_to(const ble_addr_t *addr)
{
    for (size_t i = 0; i < BITLE_BLE_MAX_CONNECTIONS; ++i) {
        if (s_connections[i].in_use && ble_addr_cmp(&s_connections[i].peer_addr, addr) == 0) {
            return true;
        }
    }
    return false;
}

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

/* Peripheral links carry our packets as notifications; central links (other
 * Bitles we dialed) carry them as writes to the peer's characteristic. */
static int link_send(ble_conn_state_t *state, const uint8_t *data, uint16_t len)
{
    if (state->is_central) {
        if (!state->remote_val_handle) {
            return BLE_HS_EINVAL;
        }
        return ble_gattc_write_no_rsp_flat(state->conn_handle, state->remote_val_handle, data, len);
    }
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om) {
        return BLE_HS_ENOMEM;
    }
    return ble_gattc_notify_custom(state->conn_handle, s_tx_val_handle, om);
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
        int rc = link_send(state, buffer, len);
        if (rc != 0) {
            ESP_LOGW(TAG, "Relay send failed conn=%u rc=%d", state->conn_handle, rc);
        } else {
            forwarded++;
        }
    }
    if (forwarded > 0) {
        ESP_LOGI(TAG, "Relayed type=0x%02X ttl=%u to %d conn(s)", packet->type, buffer[2], forwarded);
    }
}

static bool handle_inbound(uint16_t conn_handle, uint8_t *buffer, uint16_t len)
{
    bitchat_packet_t packet;
    if (!bitchat_packet_decode(buffer, len, &packet)) {
        ESP_LOGW(TAG, "Failed to decode inbound packet len=%u", len);
        return false;
    }
    dispatch_packet(conn_handle, &packet);
    relay_packet(conn_handle, buffer, len, &packet);
    bitchat_packet_free(&packet);
    return true;
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

    if (!handle_inbound(conn_handle, buffer, copied)) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
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
    if (ble_gap_adv_active()) {
        return;
    }
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

/* --- Central engine: discover and dial other Bitle nodes ----------------- */

static void central_disc_failed(uint16_t conn_handle, const char *stage, int rc)
{
    ESP_LOGW(TAG, "conn=%u central %s failed rc=%d; dropping link", conn_handle, stage, rc);
    ble_conn_state_t *state = find_conn(conn_handle);
    if (state) {
        deny_addr(&state->peer_addr, esp_timer_get_time() / 1000ULL);
    }
    ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
}

static int central_cccd_written(uint16_t conn_handle, const struct ble_gatt_error *error,
                                struct ble_gatt_attr *attr, void *arg)
{
    (void)attr;
    (void)arg;
    if (error->status != 0) {
        central_disc_failed(conn_handle, "CCCD write", error->status);
        return 0;
    }
    ble_conn_state_t *state = find_conn(conn_handle);
    if (!state) {
        return 0;
    }
    state->subscribed = true;
    ESP_LOGI(TAG, "conn=%u bitle-to-bitle link ready (val_handle=%u)",
             conn_handle, state->remote_val_handle);
    noise_notify_subscribed(conn_handle);
    return 0;
}

static int central_dsc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                          uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg)
{
    (void)chr_val_handle;
    (void)arg;
    ble_conn_state_t *state = find_conn(conn_handle);
    if (!state) {
        return 0;
    }
    if (error->status == 0 && dsc &&
        ble_uuid_cmp(&dsc->uuid.u, BLE_UUID16_DECLARE(0x2902)) == 0) {
        uint8_t enable[2] = {0x01, 0x00}; /* notifications */
        int rc = ble_gattc_write_flat(conn_handle, dsc->handle, enable, sizeof(enable),
                                      central_cccd_written, NULL);
        if (rc != 0) {
            central_disc_failed(conn_handle, "CCCD write start", rc);
        }
        return BLE_HS_EDONE; /* stop descriptor discovery */
    }
    if (error->status == BLE_HS_EDONE) {
        return 0;
    }
    if (error->status != 0) {
        central_disc_failed(conn_handle, "descriptor discovery", error->status);
    }
    return 0;
}

static int central_chr_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                          const struct ble_gatt_chr *chr, void *arg)
{
    (void)arg;
    ble_conn_state_t *state = find_conn(conn_handle);
    if (!state) {
        return 0;
    }
    if (error->status == 0 && chr) {
        state->remote_val_handle = chr->val_handle;
        return 0;
    }
    if (error->status == BLE_HS_EDONE) {
        if (!state->remote_val_handle) {
            central_disc_failed(conn_handle, "characteristic lookup", BLE_HS_ENOENT);
            return 0;
        }
        int rc = ble_gattc_disc_all_dscs(conn_handle, state->remote_val_handle,
                                         state->svc_end_handle, central_dsc_cb, NULL);
        if (rc != 0) {
            central_disc_failed(conn_handle, "descriptor discovery start", rc);
        }
        return 0;
    }
    central_disc_failed(conn_handle, "characteristic discovery", error->status);
    return 0;
}

static int central_svc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                          const struct ble_gatt_svc *service, void *arg)
{
    (void)arg;
    ble_conn_state_t *state = find_conn(conn_handle);
    if (!state) {
        return 0;
    }
    if (error->status == 0 && service) {
        state->svc_end_handle = service->end_handle;
        int rc = ble_gattc_disc_chrs_by_uuid(conn_handle, service->start_handle,
                                             service->end_handle, &s_txrx_uuid.u,
                                             central_chr_cb, NULL);
        if (rc != 0) {
            central_disc_failed(conn_handle, "characteristic discovery start", rc);
        }
        return BLE_HS_EDONE;
    }
    if (error->status == BLE_HS_EDONE) {
        if (!state->svc_end_handle) {
            central_disc_failed(conn_handle, "service lookup", BLE_HS_ENOENT);
        }
        return 0;
    }
    central_disc_failed(conn_handle, "service discovery", error->status);
    return 0;
}

static void central_start_discovery(uint16_t conn_handle)
{
    ble_gattc_exchange_mtu(conn_handle, NULL, NULL);
    int rc = ble_gattc_disc_svc_by_uuid(conn_handle, &s_service_uuid.u, central_svc_cb, NULL);
    if (rc != 0) {
        central_disc_failed(conn_handle, "service discovery start", rc);
    }
}

static void maybe_connect_to_bitle(const struct ble_gap_disc_desc *disc)
{
    uint64_t now = esp_timer_get_time() / 1000ULL;

    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data) != 0) {
        return;
    }
    if (fields.name_len != strlen(BITLE_DEVICE_NAME) ||
        memcmp(fields.name, BITLE_DEVICE_NAME, fields.name_len) != 0) {
        return; /* phones and other peripherals: connect to us, not us to them */
    }
    if (addr_denied(&disc->addr, now) || already_linked_to(&disc->addr)) {
        return;
    }
    if (count_connections(true) >= BITLE_CENTRAL_MAX_LINKS ||
        count_connections(false) + BITLE_CENTRAL_RESERVE >= BITLE_BLE_MAX_CONNECTIONS) {
        return;
    }

    ble_gap_disc_cancel();
    ESP_LOGI(TAG, "Found Bitle peer %02x:%02x:%02x:%02x:%02x:%02x; connecting",
             disc->addr.val[5], disc->addr.val[4], disc->addr.val[3],
             disc->addr.val[2], disc->addr.val[1], disc->addr.val[0]);
    int rc = ble_gap_connect(s_own_addr_type, &disc->addr, 10000, NULL, gap_event_cb, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "ble_gap_connect failed rc=%d", rc);
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
                return 0;
            }
            state->connected_at_ms = esp_timer_get_time() / 1000ULL;
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(conn, &desc) == 0) {
                state->peer_addr = desc.peer_id_addr;
                state->is_central = (desc.role == BLE_GAP_ROLE_MASTER);
            }
            ESP_LOGI(TAG, "Connected conn=%u role=%s", conn,
                     state->is_central ? "central" : "peripheral");
            if (state->is_central) {
                central_start_discovery(conn);
            }
        } else {
            ESP_LOGW(TAG, "Connect failed status=%d", event->connect.status);
        }
        /* Keep accepting phones (and other Bitles) regardless of how many
         * links are already up — advertising must survive every connect. */
        start_advertising();
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "Disconnected conn=%u reason=%d",
                 event->disconnect.conn.conn_handle, event->disconnect.reason);
        noise_reset_connection(event->disconnect.conn.conn_handle);
        drop_conn(event->disconnect.conn.conn_handle);
        start_advertising();
        return 0;

    case BLE_GAP_EVENT_DISC:
        maybe_connect_to_bitle(&event->disc);
        return 0;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        return 0;

    case BLE_GAP_EVENT_NOTIFY_RX: {
        uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
        if (len == 0 || len > BITCHAT_BLE_MAX_PACKET_SIZE) {
            return 0;
        }
        uint8_t buffer[BITCHAT_BLE_MAX_PACKET_SIZE];
        uint16_t copied = 0;
        if (ble_hs_mbuf_to_flat(event->notify_rx.om, buffer, sizeof(buffer), &copied) == 0 && copied) {
            handle_inbound(event->notify_rx.conn_handle, buffer, copied);
        }
        return 0;
    }

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

static void maybe_start_scan(uint64_t now)
{
    static uint64_t s_last_scan_ms;
    if (!s_host_synced || now - s_last_scan_ms < BITLE_SCAN_INTERVAL_MS) {
        return;
    }
    if (ble_gap_disc_active() || ble_gap_conn_active()) {
        return;
    }
    if (count_connections(true) >= BITLE_CENTRAL_MAX_LINKS ||
        count_connections(false) + BITLE_CENTRAL_RESERVE >= BITLE_BLE_MAX_CONNECTIONS) {
        return;
    }
    s_last_scan_ms = now;
    struct ble_gap_disc_params params = {
        .itvl = 0x0060,
        .window = 0x0030,
        .passive = 0,               /* active: Bitle's name lives in scan_rsp */
        .filter_duplicates = 1,
    };
    int rc = ble_gap_disc(s_own_addr_type, BITLE_SCAN_DURATION_MS, &params, gap_event_cb, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "ble_gap_disc failed rc=%d", rc);
    } else {
        ESP_LOGD(TAG, "Scanning for Bitle peers");
    }
}

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

    maybe_start_scan(now);
}

bool bitchat_ble_conn_is_central(uint16_t conn_handle)
{
    ble_conn_state_t *state = find_conn(conn_handle);
    return state && state->is_central;
}

void bitchat_ble_disconnect(uint16_t conn_handle)
{
    ble_conn_state_t *state = find_conn(conn_handle);
    if (state) {
        /* Cool-down so the scanner does not immediately re-dial a peer we
         * deliberately dropped (duplicate-link resolution). */
        deny_addr(&state->peer_addr, esp_timer_get_time() / 1000ULL);
    }
    ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
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

    int rc = link_send(state, data, (uint16_t)len);
    if (rc != 0) {
        ESP_LOGW(TAG, "send failed conn=%u rc=%d", conn_handle, rc);
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

    int rc;
    if (state->is_central) {
        rc = ble_gattc_write_no_rsp_flat(conn_handle, state->remote_val_handle, data, (uint16_t)len);
    } else {
        struct os_mbuf *om = ble_hs_mbuf_from_flat(data, (uint16_t)len);
        if (!om) {
            return ESP_ERR_NO_MEM;
        }
        rc = ble_gatts_indicate_custom(conn_handle, s_tx_val_handle, om);
    }
    if (rc != 0) {
        ESP_LOGW(TAG, "indicate failed conn=%u rc=%d", conn_handle, rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}
