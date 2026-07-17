#include "bitle_link.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "bitle_link";

typedef struct {
    bool in_use;
    uint16_t handle;
    bitle_link_type_t type;
    bitle_link_send_fn_t send_fn;
} link_entry_t;

static link_entry_t s_links[BITLE_LINK_MAX];
static SemaphoreHandle_t s_lock;

esp_err_t bitle_link_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}

static link_entry_t *find_locked(uint16_t handle)
{
    for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
        if (s_links[i].in_use && s_links[i].handle == handle) {
            return &s_links[i];
        }
    }
    return NULL;
}

esp_err_t bitle_link_register(uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn)
{
    if (!send_fn || handle == BITLE_LINK_NONE) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    if (!e) {
        for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
            if (!s_links[i].in_use) {
                e = &s_links[i];
                break;
            }
        }
    }
    if (!e) {
        xSemaphoreGive(s_lock);
        ESP_LOGW(TAG, "link table full; cannot register handle=%u", handle);
        return ESP_ERR_NO_MEM;
    }
    e->in_use = true;
    e->handle = handle;
    e->type = type;
    e->send_fn = send_fn;
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "link up handle=%u type=%s", handle, type == BITLE_LINK_BLE ? "ble" : "lora");
    return ESP_OK;
}

void bitle_link_unregister(uint16_t handle)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    if (e) {
        memset(e, 0, sizeof(*e));
    }
    xSemaphoreGive(s_lock);
}

bool bitle_link_ready(uint16_t handle)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool ready = find_locked(handle) != NULL;
    xSemaphoreGive(s_lock);
    return ready;
}

esp_err_t bitle_link_send(uint16_t handle, const uint8_t *data, uint16_t len)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    bitle_link_send_fn_t fn = e ? e->send_fn : NULL;
    xSemaphoreGive(s_lock);
    if (!fn) {
        return ESP_ERR_INVALID_STATE;
    }
    /* Send outside the lock: transport sends may block briefly. */
    return fn(handle, data, len) == 0 ? ESP_OK : ESP_FAIL;
}

int bitle_link_broadcast(uint16_t exclude_handle, const uint8_t *data, uint16_t len)
{
    /* Snapshot under the lock, send outside it. */
    struct {
        uint16_t handle;
        bitle_link_send_fn_t fn;
    } targets[BITLE_LINK_MAX];
    size_t n = 0;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
        if (s_links[i].in_use && s_links[i].handle != exclude_handle) {
            targets[n].handle = s_links[i].handle;
            targets[n].fn = s_links[i].send_fn;
            n++;
        }
    }
    xSemaphoreGive(s_lock);

    int sent = 0;
    for (size_t i = 0; i < n; ++i) {
        int rc = targets[i].fn(targets[i].handle, data, len);
        if (rc == 0) {
            sent++;
        } else {
            ESP_LOGW(TAG, "broadcast send failed handle=%u rc=%d", targets[i].handle, rc);
        }
    }
    return sent;
}
