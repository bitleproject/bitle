#include "bitchat_time.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BITCHAT_TIME_NS   "noise"
#define BITCHAT_TIME_KEY  "epoch_base"
#define MIN_VALID_EPOCH_SECONDS 1704067200ull
#define MAX_CLOCK_SKEW_SECONDS  600ull

static const char *TAG = "bitchat_time";

static uint64_t s_epoch_base_ms;
static bool s_time_valid;

static uint64_t monotonic_ms(void)
{
    return esp_timer_get_time() / 1000ULL;
}

static void persist_epoch_base(uint64_t epoch_ms)
{
    nvs_handle_t handle;
    if (nvs_open(BITCHAT_TIME_NS, NVS_READWRITE, &handle) != ESP_OK) {
        return;
    }
    nvs_set_u64(handle, BITCHAT_TIME_KEY, epoch_ms);
    nvs_commit(handle);
    nvs_close(handle);
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

esp_err_t bitchat_time_init(void)
{
    s_epoch_base_ms = load_epoch_base();
    if (s_epoch_base_ms == 0) {
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
        s_epoch_base_ms = (uint64_t)epoch * 1000ULL;
        persist_epoch_base(s_epoch_base_ms);
        ESP_LOGI(TAG, "Seeded epoch base from build %s %s -> %llu", build_date, build_time, s_epoch_base_ms);
    } else {
        ESP_LOGI(TAG, "Loaded epoch base %llu", s_epoch_base_ms);
    }
    s_time_valid = (s_epoch_base_ms / 1000ULL) >= MIN_VALID_EPOCH_SECONDS;
    return ESP_OK;
}

uint64_t bitchat_time_now_ms(void)
{
    if (!s_epoch_base_ms) {
        return 0;
    }
    return s_epoch_base_ms + monotonic_ms();
}

bool bitchat_time_is_valid(void)
{
    return s_time_valid;
}

void bitchat_time_consider_peer(uint64_t peer_timestamp_ms)
{
    if (peer_timestamp_ms == 0) {
        return;
    }
    uint64_t now_monotonic = monotonic_ms();
    uint64_t current_epoch = s_epoch_base_ms + now_monotonic;

    if ((peer_timestamp_ms / 1000ULL) < MIN_VALID_EPOCH_SECONDS) {
        return;
    }

    if (peer_timestamp_ms <= current_epoch) {
        if (current_epoch - peer_timestamp_ms > MAX_CLOCK_SKEW_SECONDS * 1000ULL) {
            s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
            persist_epoch_base(s_epoch_base_ms);
            s_time_valid = true;
            ESP_LOGI(TAG, "Epoch base adjusted backward to %llu", s_epoch_base_ms);
        }
        return;
    }

    uint64_t delta = peer_timestamp_ms - current_epoch;
    if (delta > MAX_CLOCK_SKEW_SECONDS * 1000ULL) {
        s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
        persist_epoch_base(s_epoch_base_ms);
        s_time_valid = true;
        ESP_LOGI(TAG, "Epoch base adjusted forward to %llu", s_epoch_base_ms);
    }
}

void bitchat_time_set_from_wall(uint64_t unix_ms)
{
    if (unix_ms == 0 || unix_ms / 1000ULL < MIN_VALID_EPOCH_SECONDS) {
        return;
    }
    uint64_t now_monotonic = monotonic_ms();
    s_epoch_base_ms = unix_ms - now_monotonic;
    persist_epoch_base(s_epoch_base_ms);
    s_time_valid = true;
    ESP_LOGI(TAG, "Epoch base forced to %llu", s_epoch_base_ms);
}
