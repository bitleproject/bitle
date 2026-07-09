#ifndef BITCHAT_BLE_H
#define BITCHAT_BLE_H

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITCHAT_BLE_MAX_PACKET_SIZE 520
/* messageTTLDefault upstream; a packet still at this TTL arrived directly. */
#define BITLE_ORIGIN_TTL 7

esp_err_t bitchat_ble_init(void);
esp_err_t bitchat_ble_start(void);
void bitchat_ble_poll(void);
esp_err_t bitchat_ble_send(uint16_t conn_handle, const uint8_t *data, size_t len);
esp_err_t bitchat_ble_send_with_ack(uint16_t conn_handle, const uint8_t *data, size_t len);
bool bitchat_ble_conn_subscribed(uint16_t conn_handle);
bool bitchat_ble_conn_is_central(uint16_t conn_handle);
void bitchat_ble_disconnect(uint16_t conn_handle);

#ifdef __cplusplus
}
#endif

#endif // BITCHAT_BLE_H

