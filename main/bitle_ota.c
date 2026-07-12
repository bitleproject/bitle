#include "bitle_ota.h"

#include <string.h>

#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "bitle_hash.h"
#include "nvs.h"

#include "ed25519.h"
#include "ota_owner_pubkey.h"

#define OTA_NS                 "bitleota"
#define OTA_MANIFEST_KEY       "manifest"

#define OTA_MAGIC              "BOTA"
#define OTA_SIGN_CONTEXT       "bitle-fw-v1"
#define OTA_MANIFEST_LEN       110  /* magic4 + ver4 + size4 + sha32 + chunk2 + sig64 */
#define OTA_FIELDS_OFF         4
#define OTA_FIELDS_LEN         42   /* ver4 + size4 + sha32 + chunk2 */
#define OTA_SIG_OFF            46

#define OTA_CHUNK_MAX          480
#define OTA_QUEUE_DEPTH        6
#define OTA_TASK_STACK         6144
#define OTA_RX_TIMEOUT_MS      4000
#define OTA_RX_MAX_RETRIES     40
#define OTA_OFFER_INTERVAL_MS  60000
#define OTA_HEALTH_FALLBACK_MS (30ULL * 60ULL * 1000ULL)

static const char *TAG = "bitle_ota";

typedef struct {
    uint8_t type;          /* bitchat message type 0xA0..0xA3, or 0xFF = offer */
    uint16_t conn_handle;
    uint8_t peer[8];
    uint16_t len;
    uint8_t payload[OTA_CHUNK_MAX + 16];
} ota_event_t;

typedef struct {
    uint32_t version;
    uint32_t size;
    uint8_t sha256[32];
    uint16_t chunk_size;
    uint8_t raw[OTA_MANIFEST_LEN];
} ota_manifest_t;

/* Receiver state (single transfer at a time). */
static struct {
    bool active;
    ota_manifest_t manifest;
    uint32_t next_chunk;
    uint32_t total_chunks;
    esp_ota_handle_t handle;
    const esp_partition_t *part;
    uint16_t conn_handle;
    uint8_t peer[8];
    uint64_t last_activity_ms;
    uint32_t retries;
    bitle_sha256_ctx_t sha;
} s_rx;

static ota_manifest_t s_serve_manifest;
static bool s_can_serve;
static bool s_pending_verify;
static volatile bool s_health_signal;
static uint64_t s_reboot_at_ms;
static uint64_t s_last_offer_ms[8];

static QueueHandle_t s_queue;
static TaskHandle_t s_task;

static uint64_t uptime_ms(void)
{
    return esp_timer_get_time() / 1000ULL;
}

static bool parse_manifest(const uint8_t *data, size_t len, ota_manifest_t *out)
{
    if (len != OTA_MANIFEST_LEN || memcmp(data, OTA_MAGIC, 4) != 0) {
        return false;
    }
    uint8_t signed_buf[sizeof(OTA_SIGN_CONTEXT) - 1 + OTA_FIELDS_LEN];
    memcpy(signed_buf, OTA_SIGN_CONTEXT, sizeof(OTA_SIGN_CONTEXT) - 1);
    memcpy(signed_buf + sizeof(OTA_SIGN_CONTEXT) - 1, data + OTA_FIELDS_OFF, OTA_FIELDS_LEN);
    if (ed25519_sign_open(signed_buf, sizeof(signed_buf),
                          (unsigned char *)BITLE_OTA_OWNER_PUBKEY,
                          (unsigned char *)(data + OTA_SIG_OFF)) != 0) {
        ESP_LOGW(TAG, "Manifest signature rejected");
        return false;
    }
    const uint8_t *p = data + OTA_FIELDS_OFF;
    out->version = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    out->size = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
    memcpy(out->sha256, p + 8, 32);
    out->chunk_size = ((uint16_t)p[40] << 8) | p[41];
    memcpy(out->raw, data, OTA_MANIFEST_LEN);
    if (out->size == 0 || out->chunk_size < 64 || out->chunk_size > OTA_CHUNK_MAX) {
        return false;
    }
    return true;
}

static void store_serve_manifest(const ota_manifest_t *manifest)
{
    nvs_handle_t handle;
    if (nvs_open(OTA_NS, NVS_READWRITE, &handle) != ESP_OK) {
        return;
    }
    nvs_set_blob(handle, OTA_MANIFEST_KEY, manifest->raw, OTA_MANIFEST_LEN);
    nvs_commit(handle);
    nvs_close(handle);
    s_serve_manifest = *manifest;
    s_can_serve = true;
}

static bool hash_matches_running_image(const ota_manifest_t *manifest)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running || manifest->size > running->size) {
        return false;
    }
    bitle_sha256_ctx_t ctx;
    bitle_sha256_begin(&ctx);
    uint8_t buf[1024];
    for (uint32_t off = 0; off < manifest->size; off += sizeof(buf)) {
        size_t n = manifest->size - off < sizeof(buf) ? manifest->size - off : sizeof(buf);
        if (esp_partition_read(running, off, buf, n) != ESP_OK) {
            bitle_sha256_abort(&ctx);
            return false;
        }
        bitle_sha256_update(&ctx, buf, n);
    }
    uint8_t digest[32];
    bitle_sha256_finish(&ctx, digest);
    return memcmp(digest, manifest->sha256, sizeof(digest)) == 0;
}

static void send_req(uint32_t chunk_index)
{
    uint8_t payload[8];
    payload[0] = (s_rx.manifest.version >> 24) & 0xFF;
    payload[1] = (s_rx.manifest.version >> 16) & 0xFF;
    payload[2] = (s_rx.manifest.version >> 8) & 0xFF;
    payload[3] = s_rx.manifest.version & 0xFF;
    payload[4] = (chunk_index >> 24) & 0xFF;
    payload[5] = (chunk_index >> 16) & 0xFF;
    payload[6] = (chunk_index >> 8) & 0xFF;
    payload[7] = chunk_index & 0xFF;
    noise_send_raw(s_rx.conn_handle, BITLE_MSG_OTA_REQ, s_rx.peer, payload, sizeof(payload));
}

static void send_status(uint16_t conn_handle, const uint8_t peer[8], uint8_t code)
{
    noise_send_raw(conn_handle, BITLE_MSG_OTA_STATUS, peer, &code, 1);
}

static void abort_receive(const char *reason)
{
    if (!s_rx.active) {
        return;
    }
    ESP_LOGW(TAG, "OTA receive aborted: %s (chunk %lu/%lu)", reason,
             (unsigned long)s_rx.next_chunk, (unsigned long)s_rx.total_chunks);
    esp_ota_abort(s_rx.handle);
    bitle_sha256_abort(&s_rx.sha);
    memset(&s_rx, 0, sizeof(s_rx));
}

static void handle_manifest(const ota_event_t *evt)
{
    ota_manifest_t manifest;
    if (!parse_manifest(evt->payload, evt->len, &manifest)) {
        return;
    }

    if (manifest.version == BITLE_FW_VERSION) {
        /* Manifest for the image we are already running: adopt it so this
         * node can serve peers (covers wire-flashed nodes). */
        if (!s_can_serve && hash_matches_running_image(&manifest)) {
            store_serve_manifest(&manifest);
            ESP_LOGI(TAG, "Adopted manifest for running image v%lu; now serving",
                     (unsigned long)manifest.version);
            send_status(evt->conn_handle, evt->peer, 0x01);
        }
        return;
    }
    if (manifest.version < BITLE_FW_VERSION) {
        return; /* downgrade: never */
    }
    if (s_rx.active) {
        if (manifest.version <= s_rx.manifest.version) {
            return;
        }
        abort_receive("superseded by newer manifest");
    }

    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part || manifest.size > part->size) {
        ESP_LOGE(TAG, "No usable OTA partition for %lu bytes", (unsigned long)manifest.size);
        return;
    }
    if (esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &s_rx.handle) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed");
        return;
    }
    s_rx.active = true;
    s_rx.manifest = manifest;
    s_rx.part = part;
    s_rx.conn_handle = evt->conn_handle;
    memcpy(s_rx.peer, evt->peer, sizeof(s_rx.peer));
    s_rx.next_chunk = 0;
    s_rx.total_chunks = (manifest.size + manifest.chunk_size - 1) / manifest.chunk_size;
    s_rx.retries = 0;
    s_rx.last_activity_ms = uptime_ms();
    bitle_sha256_begin(&s_rx.sha);
    ESP_LOGI(TAG, "OTA v%lu started: %lu bytes in %lu chunks of %u",
             (unsigned long)manifest.version, (unsigned long)manifest.size,
             (unsigned long)s_rx.total_chunks, manifest.chunk_size);
    send_req(0);
}

static void finish_receive(void)
{
    uint8_t digest[32];
    bitle_sha256_finish(&s_rx.sha, digest);
    if (memcmp(digest, s_rx.manifest.sha256, sizeof(digest)) != 0) {
        ESP_LOGE(TAG, "Image hash mismatch after transfer");
        esp_ota_abort(s_rx.handle);
        send_status(s_rx.conn_handle, s_rx.peer, 0xE1);
        memset(&s_rx, 0, sizeof(s_rx));
        return;
    }
    if (esp_ota_end(s_rx.handle) != ESP_OK ||
        esp_ota_set_boot_partition(s_rx.part) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to finalize OTA image");
        send_status(s_rx.conn_handle, s_rx.peer, 0xE2);
        memset(&s_rx, 0, sizeof(s_rx));
        return;
    }
    store_serve_manifest(&s_rx.manifest);
    send_status(s_rx.conn_handle, s_rx.peer, 0x00);
    ESP_LOGI(TAG, "OTA v%lu applied; rebooting shortly", (unsigned long)s_rx.manifest.version);
    memset(&s_rx, 0, sizeof(s_rx));
    s_reboot_at_ms = uptime_ms() + 3000;
}

static void handle_chunk(const ota_event_t *evt)
{
    if (!s_rx.active || evt->len < 9) {
        return;
    }
    const uint8_t *p = evt->payload;
    uint32_t version = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    uint32_t index = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
    const uint8_t *data = p + 8;
    uint16_t data_len = evt->len - 8;
    if (version != s_rx.manifest.version) {
        return;
    }
    s_rx.last_activity_ms = uptime_ms();
    if (index != s_rx.next_chunk) {
        send_req(s_rx.next_chunk); /* duplicate or out of order; re-anchor */
        return;
    }
    uint32_t expected = s_rx.manifest.size - index * s_rx.manifest.chunk_size;
    if (expected > s_rx.manifest.chunk_size) {
        expected = s_rx.manifest.chunk_size;
    }
    if (data_len != expected) {
        return;
    }
    if (esp_ota_write(s_rx.handle, data, data_len) != ESP_OK) {
        abort_receive("flash write failed");
        return;
    }
    bitle_sha256_update(&s_rx.sha, data, data_len);
    s_rx.next_chunk++;
    s_rx.retries = 0;
    if ((s_rx.next_chunk & 0x3F) == 0) {
        ESP_LOGI(TAG, "OTA progress %lu/%lu", (unsigned long)s_rx.next_chunk,
                 (unsigned long)s_rx.total_chunks);
    }
    if (s_rx.next_chunk >= s_rx.total_chunks) {
        finish_receive();
    } else {
        send_req(s_rx.next_chunk);
    }
}

static void handle_req(const ota_event_t *evt)
{
    if (!s_can_serve || evt->len < 8) {
        return;
    }
    const uint8_t *p = evt->payload;
    uint32_t version = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    uint32_t index = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
    if (version != s_serve_manifest.version) {
        return;
    }
    uint32_t offset = index * s_serve_manifest.chunk_size;
    if (offset >= s_serve_manifest.size) {
        return;
    }
    uint32_t len = s_serve_manifest.size - offset;
    if (len > s_serve_manifest.chunk_size) {
        len = s_serve_manifest.chunk_size;
    }
    uint8_t payload[8 + OTA_CHUNK_MAX];
    payload[0] = p[0]; payload[1] = p[1]; payload[2] = p[2]; payload[3] = p[3];
    payload[4] = p[4]; payload[5] = p[5]; payload[6] = p[6]; payload[7] = p[7];
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running || esp_partition_read(running, offset, payload + 8, len) != ESP_OK) {
        return;
    }
    noise_send_raw(evt->conn_handle, BITLE_MSG_OTA_CHUNK, evt->peer, payload, 8 + len);
}

static void handle_offer(const ota_event_t *evt)
{
    if (!s_can_serve || s_rx.active) {
        return;
    }
    uint64_t now = uptime_ms();
    size_t slot = evt->conn_handle % (sizeof(s_last_offer_ms) / sizeof(s_last_offer_ms[0]));
    if (s_last_offer_ms[slot] && now - s_last_offer_ms[slot] < OTA_OFFER_INTERVAL_MS) {
        return;
    }
    s_last_offer_ms[slot] = now;
    ESP_LOGI(TAG, "Offering firmware v%lu to stale peer", (unsigned long)s_serve_manifest.version);
    noise_send_raw(evt->conn_handle, BITLE_MSG_OTA_MANIFEST, evt->peer,
                   s_serve_manifest.raw, OTA_MANIFEST_LEN);
}

static void ota_task(void *arg)
{
    (void)arg;
    ota_event_t evt;
    while (true) {
        if (xQueueReceive(s_queue, &evt, pdMS_TO_TICKS(500)) == pdTRUE) {
            switch (evt.type) {
            case BITLE_MSG_OTA_MANIFEST: handle_manifest(&evt); break;
            case BITLE_MSG_OTA_CHUNK:    handle_chunk(&evt);    break;
            case BITLE_MSG_OTA_REQ:      handle_req(&evt);      break;
            case BITLE_MSG_OTA_STATUS:
                ESP_LOGI(TAG, "Peer OTA status 0x%02X", evt.len ? evt.payload[0] : 0xFF);
                break;
            case 0xFF:                   handle_offer(&evt);    break;
            default: break;
            }
        }

        uint64_t now = uptime_ms();
        if (s_rx.active && now - s_rx.last_activity_ms > OTA_RX_TIMEOUT_MS) {
            if (++s_rx.retries > OTA_RX_MAX_RETRIES) {
                abort_receive("too many retries");
            } else {
                s_rx.last_activity_ms = now;
                send_req(s_rx.next_chunk);
            }
        }
        if (s_health_signal && s_pending_verify) {
            s_pending_verify = false;
            esp_ota_mark_app_valid_cancel_rollback();
            ESP_LOGI(TAG, "Firmware v%u marked healthy; rollback cancelled", BITLE_FW_VERSION);
        }
        if (s_pending_verify && now > OTA_HEALTH_FALLBACK_MS) {
            /* No peer contact after a long time can simply mean an empty
             * field site; keep the image rather than rollback-looping. */
            s_pending_verify = false;
            esp_ota_mark_app_valid_cancel_rollback();
            ESP_LOGW(TAG, "Health fallback: marking firmware valid after %llu min uptime",
                     (unsigned long long)(now / 60000ULL));
        }
        if (s_reboot_at_ms && now >= s_reboot_at_ms) {
            esp_restart();
        }
    }
}

/* A wire-flashed node has no signed manifest for its running image and so
 * cannot serve peers. The release manifest is flashed into the fw_manifest
 * partition alongside the image; adopt it here (after verifying signature
 * and that it describes our running image) so the node serves immediately. */
static void adopt_manifest_from_partition(void)
{
    const esp_partition_t *part =
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "fw_manifest");
    if (!part) {
        return;
    }
    uint8_t raw[OTA_MANIFEST_LEN];
    if (esp_partition_read(part, 0, raw, sizeof(raw)) != ESP_OK ||
        memcmp(raw, OTA_MAGIC, 4) != 0) {
        return;
    }
    ota_manifest_t manifest;
    if (!parse_manifest(raw, sizeof(raw), &manifest)) {
        return;
    }
    if (manifest.version != BITLE_FW_VERSION) {
        return;
    }
    if (hash_matches_running_image(&manifest)) {
        store_serve_manifest(&manifest);
        ESP_LOGI(TAG, "Adopted flashed manifest for running image v%lu; serving",
                 (unsigned long)manifest.version);
    } else {
        ESP_LOGW(TAG, "fw_manifest partition does not match running image; ignoring");
    }
}

void bitle_ota_handle_packet(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    if (!s_queue || !packet->payload || packet->payload_len > sizeof(((ota_event_t *)0)->payload)) {
        return;
    }
    ota_event_t evt = {
        .type = packet->type,
        .conn_handle = conn_handle,
        .len = packet->payload_len,
    };
    memcpy(evt.peer, packet->sender_id, sizeof(evt.peer));
    memcpy(evt.payload, packet->payload, packet->payload_len);
    if (xQueueSend(s_queue, &evt, 0) != pdTRUE) {
        ESP_LOGW(TAG, "OTA queue full; dropped type 0x%02X", packet->type);
    }
}

void bitle_ota_peer_version_seen(uint16_t conn_handle, const uint8_t peer_id[8], uint32_t version)
{
    if (!s_queue || !s_can_serve || version == 0 || version >= s_serve_manifest.version) {
        return;
    }
    ota_event_t evt = {
        .type = 0xFF,
        .conn_handle = conn_handle,
    };
    memcpy(evt.peer, peer_id, sizeof(evt.peer));
    xQueueSend(s_queue, &evt, 0);
}

void bitle_ota_mark_healthy(void)
{
    s_health_signal = true;
}

bool bitle_ota_can_serve(void)
{
    return s_can_serve;
}

bool bitle_ota_busy(void)
{
    return s_rx.active;
}

esp_err_t bitle_ota_init(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (running && esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        s_pending_verify = true;
        ESP_LOGW(TAG, "Running unverified image v%u; awaiting health signal", BITLE_FW_VERSION);
    }

    nvs_handle_t handle;
    if (nvs_open(OTA_NS, NVS_READWRITE, &handle) == ESP_OK) {
        uint8_t raw[OTA_MANIFEST_LEN];
        size_t len = sizeof(raw);
        if (nvs_get_blob(handle, OTA_MANIFEST_KEY, raw, &len) == ESP_OK && len == sizeof(raw)) {
            ota_manifest_t manifest;
            /* Hash-check against the running image too: a wire reflash can
             * leave a stale same-version manifest behind, and serving
             * chunks that do not match the manifest would only waste every
             * receiver's transfer. */
            if (parse_manifest(raw, len, &manifest) && manifest.version == BITLE_FW_VERSION &&
                hash_matches_running_image(&manifest)) {
                s_serve_manifest = manifest;
                s_can_serve = true;
                ESP_LOGI(TAG, "Serving firmware v%lu (%lu bytes)",
                         (unsigned long)manifest.version, (unsigned long)manifest.size);
            } else {
                nvs_erase_key(handle, OTA_MANIFEST_KEY);
                nvs_commit(handle);
            }
        }
        nvs_close(handle);
    }

    if (!s_can_serve) {
        adopt_manifest_from_partition();
    }

    s_queue = xQueueCreate(OTA_QUEUE_DEPTH, sizeof(ota_event_t));
    if (!s_queue) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(ota_task, "bitle_ota", OTA_TASK_STACK, NULL, tskIDLE_PRIORITY + 2, &s_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "OTA ready (firmware v%u, %s)", BITLE_FW_VERSION,
             s_can_serve ? "serving" : "receive-only");
    return ESP_OK;
}
