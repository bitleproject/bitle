#include "bitchat_ble.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_nimble_hci.h"
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
} ble_conn_state_t;

static ble_conn_state_t s_connections[BITLE_BLE_MAX_CONNECTIONS];
static int gap_event_cb(struct ble_gap_event *event, void *arg);

/* 8f8f91f2-e88d-4d55-bbe2-4fb55c1e58fa */
static const ble_uuid128_t s_service_uuid =
    BLE_UUID128_INIT(0xfa, 0x58, 0x1e, 0x5c, 0xb5, 0x4f, 0xe2, 0xbb,
                     0x55, 0x4d, 0x8d, 0xe8, 0xf2, 0x91, 0x8f, 0x8f);
/* 8f8f91f3-e88d-4d55-bbe2-4fb55c1e58fa */
static const ble_uuid128_t s_txrx_uuid =
    BLE_UUID128_INIT(0xfa, 0x58, 0x1e, 0x5c, 0xb5, 0x4f, 0xe2, 0xbb,
                     0x55, 0x4d, 0x8d, 0xe8, 0xf3, 0x91, 0x8f, 0x8f);

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

static void dispatch_packet(uint16_t conn_handle, const bitchat_packet_t *packet)
{
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
    case BITCHAT_MSG_VERSION_HELLO:
    case BITCHAT_MSG_VERSION_ACK:
        noise_handle_version_message(conn_handle, packet);
        break;
    case BITCHAT_MSG_MESSAGE:
        noise_handle_public_message(conn_handle, packet);
        break;
    default:
        ESP_LOGW(TAG, "Unhandled packet type 0x%02X", packet->type);
        break;
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
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (const uint8_t *)BITLE_DEVICE_NAME;
    fields.name_len = (uint8_t)strlen(BITLE_DEVICE_NAME);
    fields.name_is_complete = 1;
    fields.uuids128 = (ble_uuid128_t *)&s_service_uuid;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed rc=%d", rc);
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
        if (state) {
            state->subscribed = event->subscribe.cur_notify != 0 ||
                                event->subscribe.cur_indicate != 0;
        }
        ESP_LOGI(TAG, "Subscribe conn=%u notify=%d indicate=%d",
                 event->subscribe.conn_handle,
                 event->subscribe.cur_notify,
                 event->subscribe.cur_indicate);
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

void bitchat_ble_poll(void)
{
    /* Event-driven through NimBLE callbacks. */
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

    int rc = ble_gattc_notify_custom(conn_handle, s_tx_val_handle, om);
    if (rc != 0) {
        ESP_LOGW(TAG, "notify(ack-path) failed conn=%u rc=%d", conn_handle, rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}
