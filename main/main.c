#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "bitchat_ble.h"
#include "bitchat_time.h"
#include "bitle_ota.h"
#include "noise_handshake.h"
#include "packet_codec.h"

static const char *TAG = "bitle_main";

static void bitle_main_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "Bitle task running");

    while (true) {
        bitchat_ble_poll();
        noise_poll();
        bitchat_time_poll();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "Starting Bitle firmware");

    ESP_ERROR_CHECK(bitchat_time_init());
    ESP_ERROR_CHECK(bitchat_noise_init());
    ESP_ERROR_CHECK(bitle_ota_init());
    packet_codec_init();
    if (!packet_codec_self_test()) {
        ESP_LOGE(TAG, "Packet codec self-test failed");
        abort();
    }

    ESP_ERROR_CHECK(bitchat_ble_init());
    ESP_ERROR_CHECK(bitchat_ble_start());

    xTaskCreate(bitle_main_task, "bitle_main", 8192, NULL, tskIDLE_PRIORITY + 5, NULL);
}
