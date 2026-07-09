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
/* Anti-ratchet anchor: the wall clock and the monotonic time at the last
 * confident sync. A legitimate peer's clock advances at real (monotonic)
 * rate, so an accepted forward time must never exceed anchor_wall + elapsed
 * monotonic + skew. This caps forward drift to real-time speed and defeats
 * the "+skew per packet" walk-forward attack. Guarded by s_time_lock. */
static uint64_t s_anchor_wall_ms;
static uint64_t s_anchor_mono_ms;
/* True once our clock traces to a phone (a non-infra peer), directly or via
 * an authoritative Bitle. Governs whether we accept large corrections. */
static bool s_time_authoritative;

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
    uint64_t mono = monotonic_ms();
    taskENTER_CRITICAL(&s_time_lock);
    s_last_persist_uptime_ms = mono; /* 64-bit: guard against torn access */
    taskEXIT_CRITICAL(&s_time_lock);
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

    const uint64_t skew_ms = MAX_CLOCK_SKEW_SECONDS * 1000ULL;

    /* Do the whole read-modify-write under one lock with a single monotonic
     * snapshot so a concurrent call cannot double-acquire or interleave a
     * stale base. NVS/logging happen after the lock is released, driven by
     * the captured decision. */
    bool acquired = false;   /* first-ever sync this boot */
    bool ignored = false;
    uint64_t ignored_delta = 0;

    taskENTER_CRITICAL(&s_time_lock);
    uint64_t now_monotonic = monotonic_ms();
    if (!s_peer_synced) {
        /* Initial acquisition: with no reference of our own we must trust the
         * first peer we hear (in first contact, the operator's own phone).
         * Accept it and anchor; the anchor bounds all later movement. */
        s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
        s_time_valid = true;
        s_peer_synced = true;
        s_sync_generation++;
        s_anchor_wall_ms = peer_timestamp_ms;
        s_anchor_mono_ms = now_monotonic;
        acquired = true;
    } else {
        uint64_t current_epoch = s_epoch_base_ms + now_monotonic;
        uint64_t delta = peer_timestamp_ms > current_epoch
                             ? peer_timestamp_ms - current_epoch
                             : current_epoch - peer_timestamp_ms;
        /* Reject anything outside the skew window of our established clock:
         * blocks the single-packet far-future poison. */
        if (delta > skew_ms) {
            ignored = true;
            ignored_delta = delta;
        } else if (peer_timestamp_ms > current_epoch) {
            /* Ahead and in-window: forward-track for reply ordering, but cap
             * against the anchor so the clock cannot be ratcheted faster than
             * real time by a stream of just-in-window packets. */
            uint64_t projected_cap = s_anchor_wall_ms +
                                     (now_monotonic - s_anchor_mono_ms) + skew_ms;
            if (peer_timestamp_ms <= projected_cap) {
                s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
            } else {
                ignored = true;
                ignored_delta = peer_timestamp_ms - projected_cap;
            }
        }
    }
    taskEXIT_CRITICAL(&s_time_lock);

    if (acquired) {
        persist_wall_estimate(peer_timestamp_ms);
        ESP_LOGI(TAG, "Initial clock acquired from peer: %llu", (unsigned long long)peer_timestamp_ms);
    } else if (ignored) {
        ESP_LOGW(TAG, "Ignoring out-of-window peer time (delta %llus)",
                 (unsigned long long)(ignored_delta / 1000ULL));
    }
}

bool bitchat_time_is_authoritative(void)
{
    return s_time_authoritative;
}

void bitchat_time_consider_peer_announce(uint64_t peer_timestamp_ms,
                                         bool peer_is_infra, bool peer_is_authoritative)
{
    if (peer_timestamp_ms == 0 ||
        (peer_timestamp_ms / 1000ULL) < MIN_VALID_EPOCH_SECONDS) {
        return;
    }
    const uint64_t skew_ms = MAX_CLOCK_SKEW_SECONDS * 1000ULL;
    const bool source_is_phone = !peer_is_infra;
    const bool source_authoritative = source_is_phone || peer_is_authoritative;

    bool changed = false;   /* clock (re)acquired -> persist + re-announce */
    bool upgraded = false;  /* only the authority flag flipped */
    uint64_t new_wall = 0;

    taskENTER_CRITICAL(&s_time_lock);
    uint64_t now_monotonic = monotonic_ms();
    if (!s_peer_synced) {
        s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
        s_time_valid = true;
        s_peer_synced = true;
        s_sync_generation++;
        s_anchor_wall_ms = peer_timestamp_ms;
        s_anchor_mono_ms = now_monotonic;
        s_time_authoritative = source_authoritative;
        changed = true;
        new_wall = peer_timestamp_ms;
    } else {
        uint64_t current_epoch = s_epoch_base_ms + now_monotonic;
        uint64_t delta = peer_timestamp_ms > current_epoch
                             ? peer_timestamp_ms - current_epoch
                             : current_epoch - peer_timestamp_ms;
        /* A phone always corrects us; an authoritative Bitle corrects us only
         * while we are not yet authoritative (propagation, not poisoning). */
        bool allow_large = source_is_phone || (peer_is_authoritative && !s_time_authoritative);
        if (delta <= skew_ms) {
            if (peer_timestamp_ms > current_epoch) {
                uint64_t cap = s_anchor_wall_ms +
                               (now_monotonic - s_anchor_mono_ms) + skew_ms;
                if (peer_timestamp_ms <= cap) {
                    s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
                }
            }
            if (source_authoritative && !s_time_authoritative) {
                s_time_authoritative = true;
                s_sync_generation++; /* re-announce carrying the authority flag */
                upgraded = true;
            }
        } else if (allow_large) {
            s_epoch_base_ms = peer_timestamp_ms - now_monotonic;
            s_anchor_wall_ms = peer_timestamp_ms;
            s_anchor_mono_ms = now_monotonic;
            s_sync_generation++;
            if (source_authoritative) {
                s_time_authoritative = true;
            }
            changed = true;
            new_wall = peer_timestamp_ms;
        }
        /* else: non-authoritative and out of window -> ignore (anti-poison) */
    }
    taskEXIT_CRITICAL(&s_time_lock);

    if (changed) {
        persist_wall_estimate(new_wall);
        ESP_LOGI(TAG, "Clock corrected by %s peer to %llu",
                 source_is_phone ? "phone" : "authoritative", (unsigned long long)new_wall);
    } else if (upgraded) {
        ESP_LOGI(TAG, "Clock now authoritative (phone-traced)");
    }
}

void bitchat_time_set_from_wall(uint64_t unix_ms)
{
    if (unix_ms == 0 || unix_ms / 1000ULL < MIN_VALID_EPOCH_SECONDS) {
        return;
    }
    taskENTER_CRITICAL(&s_time_lock);
    uint64_t now_monotonic = monotonic_ms();
    s_epoch_base_ms = unix_ms - now_monotonic;
    s_time_valid = true;
    s_peer_synced = true;
    s_sync_generation++;
    s_anchor_wall_ms = unix_ms;      /* trusted source re-anchors the clock */
    s_anchor_mono_ms = now_monotonic;
    s_time_authoritative = true;
    taskEXIT_CRITICAL(&s_time_lock);
    persist_wall_estimate(unix_ms);
    ESP_LOGI(TAG, "Epoch base forced to %llu", (unsigned long long)(unix_ms - now_monotonic));
}

void bitchat_time_poll(void)
{
    uint64_t uptime = monotonic_ms();
    taskENTER_CRITICAL(&s_time_lock);
    uint64_t last = s_last_persist_uptime_ms;
    taskEXIT_CRITICAL(&s_time_lock);
    if (uptime - last < PERSIST_INTERVAL_MS) {
        return;
    }
    uint64_t now = bitchat_time_now_ms();
    if (now) {
        persist_wall_estimate(now);
    }
}
