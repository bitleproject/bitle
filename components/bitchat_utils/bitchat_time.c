#include "bitchat_time.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BITCHAT_TIME_NS   "noise"
#define BITCHAT_TIME_KEY  "epoch_base"
#define MIN_VALID_EPOCH_SECONDS 1704067200ull
/* iOS drops any packet whose header timestamp is more than 120 s from its own
 * clock (BLEIngressPacketGuard.maxTimestampSkewMs), so follow peers well
 * within that window. */
#define MAX_CLOCK_SKEW_SECONDS  30ull
#define PERSIST_INTERVAL_MS     (6ULL * 60ULL * 60ULL * 1000ULL)

static const char *TAG = "bitchat_time";

static portMUX_TYPE s_time_lock = portMUX_INITIALIZER_UNLOCKED;
static uint64_t s_epoch_base_ms;
static bool s_time_valid;
static bool s_peer_synced;
static uint32_t s_sync_generation;
static uint64_t s_last_persist_uptime_ms;

static uint64_t monotonic_ms(void)
{
    return esp_timer_get_time() / 1000ULL;
}

/* Persists the current wall-clock estimate (not the boot-relative base) so a
 * reboot resumes from the last known "now" instead of rewinding by uptime. */
static void persist_wall_estimate(uint64_t wall_ms)
{
    nvs_handle_t handle;
    if (nvs_open(BITCHAT_TIME_NS, NVS_READWRITE, &handle) != ESP_OK) {
        return;
    }
    nvs_set_u64(handle, BITCHAT_TIME_KEY, wall_ms);
    nvs_commit(handle);
    nvs_close(handle);
    s_last_persist_uptime_ms = monotonic_ms();
}

static uint64_t load_epoch_base(void)
{
    nvs_handle_t handle;
    uint64_t value = 0;
    if (nvs_open(BITCHAT_TIME_NS, NVS_READWRITE, &handle) == ESP_OK) {
        if (nvs_get_u64(handle, BITCHAT_TIME_KEY, &value) != ESP_OK) {
            value = 0;
        }
        nvs_close(handle);
    }
    return value;
}

static uint64_t build_epoch_ms(void)
{
    const char *build_date = __DATE__;
    const char *build_time = __TIME__;
    struct tm tm_build = {0};
    char date_buf[16];
    char time_buf[16];
    strlcpy(date_buf, build_date, sizeof(date_buf));
    strlcpy(time_buf, build_time, sizeof(time_buf));
    char month_str[4] = {0};
    int day = 0, year = 0;
    sscanf(date_buf, "%3s %d %d", month_str, &day, &year);
    int month = 0;
    static const char *months = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *pos = strstr(months, month_str);
    if (pos) {
        month = (int)((pos - months) / 3) + 1;
    }
    int hour = 0, min = 0, sec = 0;
    sscanf(time_buf, "%d:%d:%d", &hour, &min, &sec);
    tm_build.tm_year = year >= 1900 ? year - 1900 : 125;
    tm_build.tm_mon = month ? month - 1 : 0;
    tm_build.tm_mday = day ? day : 1;
    tm_build.tm_hour = hour;
    tm_build.tm_min = min;
    tm_build.tm_sec = sec;
    time_t epoch = mktime(&tm_build);
    if (epoch < MIN_VALID_EPOCH_SECONDS) {
        epoch = MIN_VALID_EPOCH_SECONDS;
    }
    return (uint64_t)epoch * 1000ULL;
}

esp_err_t bitchat_time_init(void)
{
    uint64_t stored = load_epoch_base();
    uint64_t build_ms = build_epoch_ms();
    /* Never boot with a clock older than the firmware build. */
    uint64_t base = stored > build_ms ? stored : build_ms;
    taskENTER_CRITICAL(&s_time_lock);
    s_epoch_base_ms = base;
    s_time_valid = (base / 1000ULL) >= MIN_VALID_EPOCH_SECONDS;
    taskEXIT_CRITICAL(&s_time_lock);
    if (stored != base) {
        persist_wall_estimate(base);
    }
    ESP_LOGI(TAG, "Epoch base %llu (stored=%llu build=%llu)",
             (unsigned long long)base, (unsigned long long)stored, (unsigned long long)build_ms);
    return ESP_OK;
}

uint64_t bitchat_time_now_ms(void)
{
    taskENTER_CRITICAL(&s_time_lock);
    uint64_t base = s_epoch_base_ms;
    taskEXIT_CRITICAL(&s_time_lock);
    if (!base) {
        return 0;
    }
    return base + monotonic_ms();
}

bool bitchat_time_is_valid(void)
{
    return s_time_valid;
}

bool bitchat_time_is_peer_synced(void)
{
    return s_peer_synced;
}

uint32_t bitchat_time_sync_generation(void)
{
    return s_sync_generation;
}

void bitchat_time_consider_peer(uint64_t peer_timestamp_ms)
{
    if (peer_timestamp_ms == 0 ||
        (peer_timestamp_ms / 1000ULL) < MIN_VALID_EPOCH_SECONDS) {
        return;
    }

    uint64_t now_monotonic = monotonic_ms();
    uint64_t current_epoch = bitchat_time_now_ms();
    const uint64_t skew_ms = MAX_CLOCK_SKEW_SECONDS * 1000ULL;
    const uint64_t big_correction_ms = 60000ULL;

    if (peer_timestamp_ms > current_epoch) {
        /* Track peer clocks forward with no threshold: our clock is always
         * at least the newest timestamp heard, so replies to a message can
         * never be stamped earlier than the message itself. Only large
         * corrections are worth an NVS write and a re-announce. */
        uint64_t delta = peer_timestamp_ms - current_epoch;
        taskENTER_CRITICAL(&s_time_lock);
        s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
        s_time_valid = true;
        taskEXIT_CRITICAL(&s_time_lock);
        if (delta > big_correction_ms || !s_peer_synced) {
            s_peer_synced = true;
            s_sync_generation++;
            persist_wall_estimate(peer_timestamp_ms);
            ESP_LOGI(TAG, "Epoch base adjusted forward by %llu ms to %llu",
                     (unsigned long long)delta, (unsigned long long)peer_timestamp_ms);
        }
        return;
    }

    /* Peer timestamp is not ahead of us. Before the first sync this can mean
     * our build/NVS seed runs fast, so correct backward once; afterwards a
     * lower timestamp is just an older (possibly relayed) packet. */
    uint64_t behind = current_epoch - peer_timestamp_ms;
    if (!s_peer_synced) {
        if (behind > skew_ms) {
            taskENTER_CRITICAL(&s_time_lock);
            s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
            s_time_valid = true;
            taskEXIT_CRITICAL(&s_time_lock);
            ESP_LOGI(TAG, "Epoch base adjusted backward to %llu", (unsigned long long)peer_timestamp_ms);
            persist_wall_estimate(peer_timestamp_ms);
        } else {
            ESP_LOGI(TAG, "Epoch confirmed by peer at %llu", (unsigned long long)current_epoch);
            persist_wall_estimate(current_epoch);
        }
        s_peer_synced = true;
        s_sync_generation++;
    }
}

void bitchat_time_set_from_wall(uint64_t unix_ms)
{
    if (unix_ms == 0 || unix_ms / 1000ULL < MIN_VALID_EPOCH_SECONDS) {
        return;
    }
    uint64_t now_monotonic = monotonic_ms();
    taskENTER_CRITICAL(&s_time_lock);
    s_epoch_base_ms = unix_ms - now_monotonic;
    s_time_valid = true;
    taskEXIT_CRITICAL(&s_time_lock);
    s_peer_synced = true;
    s_sync_generation++;
    persist_wall_estimate(unix_ms);
    ESP_LOGI(TAG, "Epoch base forced to %llu", (unsigned long long)(unix_ms - now_monotonic));
}

void bitchat_time_poll(void)
{
    uint64_t uptime = monotonic_ms();
    if (uptime - s_last_persist_uptime_ms < PERSIST_INTERVAL_MS) {
        return;
    }
    uint64_t now = bitchat_time_now_ms();
    if (now) {
        persist_wall_estimate(now);
    }
}
