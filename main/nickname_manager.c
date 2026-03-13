#include "nickname_manager.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "noise_handshake.h"

#define NICKNAME_NAMESPACE "noise"
#define NICKNAME_KEY "nickname"
#define NICKNAME_MAX_CUSTOM_LEN 31

static const char *TAG = "nickname";

static bool nickname_is_deterministic(const char *nickname)
{
    if (!nickname) {
        return false;
    }
    if (strlen(nickname) != 8) {
        return false;
    }
    if (strncmp(nickname, "anon", 4) != 0) {
        return false;
    }
    for (int i = 4; i < 8; ++i) {
        if (nickname[i] < '0' || nickname[i] > '9') {
            return false;
        }
    }
    return true;
}

static bool nickname_is_custom_valid(const char *nickname)
{
    if (!nickname) {
        return false;
    }
    size_t len = strnlen(nickname, NICKNAME_MAX_CUSTOM_LEN + 1);
    if (len == 0 || len > NICKNAME_MAX_CUSTOM_LEN) {
        return false;
    }
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)nickname[i];
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

static uint16_t nickname_suffix_from_peer_id(const uint8_t *peer_id, size_t len)
{
    // Simple deterministic suffix: interpret first two bytes as big-endian
    if (!peer_id || len < 2) {
        return 0;
    }
    uint16_t value = ((uint16_t)peer_id[0] << 8) | peer_id[1];
    // Fold down using XOR with next bytes for more entropy
    for (size_t i = 2; i < len; ++i) {
        value ^= ((uint16_t)peer_id[i] << ((i & 1) ? 0 : 8));
    }
    return value % 10000;
}

static void nickname_generate(char *out_nickname, size_t max_len)
{
    if (!out_nickname || max_len < 9) {
        return;
    }
    const uint8_t *peer_id = noise_get_local_peer_id();
    uint16_t suffix = nickname_suffix_from_peer_id(peer_id, 8);
    snprintf(out_nickname, max_len, "anon%04u", (unsigned)suffix);
}

static esp_err_t nickname_store(const char *nickname)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NICKNAME_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }
    err = nvs_set_str(handle, NICKNAME_KEY, nickname);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Saved nickname: %s", nickname);
    } else {
        ESP_LOGE(TAG, "Failed to save nickname: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t nickname_init(char *out_nickname, size_t max_len)
{
    if (!out_nickname || max_len < 2) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NICKNAME_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    size_t required = max_len;
    err = nvs_get_str(handle, NICKNAME_KEY, out_nickname, &required);
    nvs_close(handle);

    if (err == ESP_OK) {
        if (nickname_is_custom_valid(out_nickname)) {
            ESP_LOGI(TAG, "Loaded nickname: %s", out_nickname);
            return ESP_OK;
        }
        if (nickname_is_deterministic(out_nickname)) {
            const uint8_t *peer_id = noise_get_local_peer_id();
            uint16_t expected = nickname_suffix_from_peer_id(peer_id, 8);
            uint16_t stored = (uint16_t)strtol(out_nickname + 4, NULL, 10);
            if (stored == expected) {
                ESP_LOGI(TAG, "Loaded nickname: %s", out_nickname);
                return ESP_OK;
            }
            ESP_LOGW(TAG, "Nickname %s mismatches deterministic suffix %04u, regenerating", out_nickname, expected);
        } else {
            ESP_LOGW(TAG, "Nickname in NVS not printable, regenerating");
        }
    }

    if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "Invalid nickname in NVS or read error, regenerating");
    }

    nickname_generate(out_nickname, max_len);
    if (!nickname_is_deterministic(out_nickname)) {
        strcpy(out_nickname, "anon0000");
    }
    nickname_store(out_nickname);
    return ESP_OK;
}

esp_err_t nickname_set(const char *nickname)
{
    if (!nickname_is_custom_valid(nickname)) {
        ESP_LOGW(TAG, "Attempted to set invalid nickname: %s", nickname ? nickname : "(null)");
        return ESP_ERR_INVALID_ARG;
    }
    return nickname_store(nickname);
}

esp_err_t nickname_regenerate(char *out_nickname, size_t max_len)
{
    if (!out_nickname || max_len < 9) {
        return ESP_ERR_INVALID_ARG;
    }
    nickname_generate(out_nickname, max_len);
    if (!nickname_is_deterministic(out_nickname)) {
        strcpy(out_nickname, "anon0000");
    }
    return nickname_store(out_nickname);
}
