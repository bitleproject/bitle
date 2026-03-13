#ifndef NOISE_HANDSHAKE_H
#define NOISE_HANDSHAKE_H

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NOISE_HANDSHAKE_TASK_PRIORITY    (tskIDLE_PRIORITY + 3)
#define NOISE_HANDSHAKE_TASK_STACK_WORDS 8192

typedef enum {
    BITCHAT_MSG_ANNOUNCE = 0x01,
    BITCHAT_MSG_MESSAGE = 0x02,
    BITCHAT_MSG_LEAVE = 0x03,
    BITCHAT_MSG_NOISE_HANDSHAKE = 0x10,
    BITCHAT_MSG_NOISE_ENCRYPTED = 0x11,
    BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE = 0x13,
    BITCHAT_MSG_VERSION_HELLO = 0x20,
    BITCHAT_MSG_VERSION_ACK = 0x21,
} bitchat_message_type_t;

typedef enum {
    BITCHAT_NOISE_PAYLOAD_PRIVATE_MESSAGE = 0x01,
    BITCHAT_NOISE_PAYLOAD_READ_RECEIPT = 0x02,
    BITCHAT_NOISE_PAYLOAD_DELIVERED = 0x03,
    BITCHAT_NOISE_PAYLOAD_VERIFY_CHALLENGE = 0x10,
    BITCHAT_NOISE_PAYLOAD_VERIFY_RESPONSE = 0x11,
} bitchat_noise_payload_type_t;

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t ttl;
    uint64_t timestamp_ms;
    uint8_t sender_id[8];
    uint8_t recipient_id[8];
    bool has_recipient;
    uint8_t *payload;
    uint16_t payload_len;
    uint8_t signature[64];
    bool has_signature;
} bitchat_packet_t;

typedef enum {
    NOISE_EVT_START,
    NOISE_EVT_PROCESS
} noise_evt_type_t;

void noise_handle_version_message(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_public_message(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_handshake(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_identity_announce(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_announce(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_encrypted(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_reset_connection(uint16_t conn_handle);
const uint8_t *noise_get_local_peer_id(void);
const uint8_t *noise_get_static_public_key(void);
void noise_begin_handshake(uint16_t conn_handle, const uint8_t peer_id[8], const char *nickname);
bool noise_can_begin_handshake(uint16_t conn_handle);
bool noise_send_encrypted(uint16_t conn_handle, bitchat_noise_payload_type_t payload_type, const uint8_t *payload, size_t payload_len);
void noise_poll(void);
esp_err_t bitchat_noise_init(void);

#ifdef __cplusplus
}
#endif

#endif // NOISE_HANDSHAKE_H
