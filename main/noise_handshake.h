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
    BITCHAT_MSG_COURIER_ENVELOPE = 0x04,
    BITCHAT_MSG_NOISE_HANDSHAKE = 0x10,
    BITCHAT_MSG_NOISE_ENCRYPTED = 0x11,
    /* Legacy type kept for older clients; consolidated out of the current
     * upstream protocol (identity now rides in the ANNOUNCE TLVs). */
    BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE = 0x13,
    /* Current upstream assignments — these were VERSION_HELLO/VERSION_ACK in
     * the pre-consolidation protocol and must never be answered as such. */
    BITCHAT_MSG_FRAGMENT = 0x20,
    BITCHAT_MSG_REQUEST_SYNC = 0x21,
    BITCHAT_MSG_PREKEY_BUNDLE = 0x24,
    BITCHAT_MSG_GROUP_MESSAGE = 0x25,
    /* Bitle-private OTA types, outside the upstream range. Phones ignore
     * them locally but relay them, so updates can cross phone bridges. */
    BITLE_MSG_OTA_MANIFEST = 0xA0,
    BITLE_MSG_OTA_REQ = 0xA1,
    BITLE_MSG_OTA_CHUNK = 0xA2,
    BITLE_MSG_OTA_STATUS = 0xA3,
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
    bool is_compressed;
    bool is_rsr;               /* flag 0x10: solicited sync response replay */
    uint8_t *payload;
    uint16_t payload_len;
    uint8_t signature[64];
    bool has_signature;
} bitchat_packet_t;

typedef enum {
    NOISE_EVT_START,
    NOISE_EVT_PROCESS,
    NOISE_EVT_ANNOUNCE,
    NOISE_EVT_IDENTITY,
    NOISE_EVT_ENCRYPTED,
    NOISE_EVT_SUBSCRIBED,
    NOISE_EVT_DISCONNECT,
    NOISE_EVT_COURIER,
    NOISE_EVT_SYNC
} noise_evt_type_t;

void noise_handle_courier(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_request_sync(uint16_t conn_handle, const bitchat_packet_t *packet);

void noise_handle_public_message(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_handshake(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_identity_announce(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_announce(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_handle_encrypted(uint16_t conn_handle, const bitchat_packet_t *packet);
void noise_reset_connection(uint16_t conn_handle);
void noise_notify_subscribed(uint16_t conn_handle);
const uint8_t *noise_get_local_peer_id(void);
const uint8_t *noise_get_static_public_key(void);
void noise_begin_handshake(uint16_t conn_handle, const uint8_t peer_id[8], const char *nickname);
bool noise_can_begin_handshake(uint16_t conn_handle);
bool noise_send_encrypted(uint16_t conn_handle, bitchat_noise_payload_type_t payload_type, const uint8_t *payload, size_t payload_len);
/* Sends an unsigned, unencrypted packet of the given type (used for the
 * Bitle OTA types; image integrity comes from the signed manifest). */
esp_err_t noise_send_raw(uint16_t conn_handle, bitchat_message_type_t type, const uint8_t recipient[8], const uint8_t *payload, size_t payload_len);
/* Full-control send: explicit TTL and optional Ed25519 packet signature.
 * requestSync (ttl 0, signed) and courier handovers (ttl 7, signed) use it. */
esp_err_t noise_send_packet(uint16_t conn_handle, bitchat_message_type_t type, const uint8_t recipient[8], const uint8_t *payload, size_t payload_len, uint8_t ttl, bool sign);

/* Identity of the direct peer on a connection, learned from its announce.
 * Returns false until a direct announce has been parsed. *verified reflects
 * whether the announce's Ed25519 packet signature checked out. */
bool noise_get_peer_identity(uint16_t conn_handle, uint8_t noise_key[32], uint8_t sign_key[32], bool *verified);

/* Verifies an inbound packet's Ed25519 signature against a signing key
 * (rebuilds the padded canonical bytes exactly as the phones do). */
bool noise_verify_packet_signature(const bitchat_packet_t *packet, const uint8_t sign_key[32]);
void noise_poll(void);
esp_err_t bitchat_noise_init(void);

#ifdef __cplusplus
}
#endif

#endif // NOISE_HANDSHAKE_H
