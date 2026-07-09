#include "noise_handshake.h"

#include "esp_check.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "bitchat_ble.h"
#include "bitchat_time.h"
#include "bitle_ota.h"
#include "nickname_manager.h"
#include "packet_codec.h"

#include "noise/protocol.h"
#include "noise/protocol/names.h"
#include "noise/protocol/constants.h"
#include "noise/protocol/dhstate.h"
#include "noise/protocol/cipherstate.h"
#include "noise/protocol/buffer.h"
#include "noise/protocol/errors.h"
#include "mbedtls/sha256.h"
#include "ed25519.h"

#define NOISE_STATIC_KEY_NS       "noise"
#define NOISE_STATIC_KEY_KEY      "static"
#define NOISE_PEER_ID_KEY         "peer_id"
#define NOISE_SIGN_PUB_KEY        "sign_pk"
#define NOISE_SIGN_PRIV_KEY       "sign_sk"
#define NOISE_NICKNAME_KEY        "nickname"

#define NOISE_PROTOCOL_NAME       "Noise_XX_25519_ChaChaPoly_SHA256"
#define NOISE_PROLOGUE            ""

#define NOISE_MAX_SESSIONS        CONFIG_BT_NIMBLE_MAX_CONNECTIONS
#define NOISE_QUEUE_DEPTH         12
#define NOISE_MESSAGE_MAX         256
#define NOISE_EVENT_PAYLOAD_MAX   320
#define NOISE_PACKET_TTL          7
#define NOISE_MAX_ENCRYPTED_PAYLOAD 320
#define ANNOUNCE_INTERVAL_MS      (10 * 1000ULL)

#define BITLE_AUTO_REPLY_TEXT \
    "This is an automated response: Bitle is a relay node designed to " \
    "expand the reach of bluetooth mesh networks. It relays encrypted " \
    "packets while maintaining e2e encryption. bitle.org."

static const char *TAG = "noise";
static const char IDENTITY_BINDING_PREFIX[] = "bitchat-announce-v1";

static uint8_t s_static_private[32];
static uint8_t s_static_public[32];
static uint8_t s_peer_id[8];
static uint8_t s_ed25519_private[32];
static uint8_t s_ed25519_public[32];
static char s_nickname[32];

typedef struct {
    bool in_use;
    uint16_t conn_handle;
    bool initiator;
    bool established;
    uint8_t peer_id[8];
    NoiseHandshakeState *handshake;
    NoiseCipherState *tx_cipher;
    NoiseCipherState *rx_cipher;
    uint8_t handshake_hash[64];
    size_t handshake_hash_len;
    uint64_t last_announce_ms;
    bool identity_sent;
    uint32_t sent_sync_gen;
    uint32_t tx_nonce;
    bool auto_replied;
    bool direct_peer;
    uint8_t hs_attempts;
    uint64_t next_hs_ms;
} noise_session_t;

typedef struct {
    bool valid;
    bool verified;              /* Ed25519 packet signature checked out */
    uint64_t timestamp_ms;
    uint32_t fw_version;        /* Bitle TLV 0xB0; 0 for phones/older nodes */
    uint8_t nickname_len;
    char nickname[sizeof(s_nickname)];
    uint8_t peer_id[8];
    uint8_t noise_key[32];
    uint8_t sign_key[32];
} noise_identity_t;

typedef struct {
    noise_evt_type_t type;
    uint16_t conn_handle;
    bool initiator;
    /* Header fields needed to rebuild the canonical bytes for signature
     * verification on the worker task. */
    uint64_t timestamp_ms;
    uint8_t ttl;
    bool has_signature;
    uint8_t signature[64];
    uint8_t peer_id[8];
    uint8_t payload[NOISE_EVENT_PAYLOAD_MAX];
    uint16_t payload_len;
} noise_event_t;

static noise_session_t s_sessions[NOISE_MAX_SESSIONS];
static noise_identity_t s_identities[NOISE_MAX_SESSIONS];
static bool s_identity_pending[NOISE_MAX_SESSIONS];
static StaticQueue_t s_queue_struct;
static uint8_t s_queue_storage[NOISE_QUEUE_DEPTH * sizeof(noise_event_t)];
static QueueHandle_t s_event_queue;
static StaticTask_t s_task_struct;
static StackType_t s_task_stack[NOISE_HANDSHAKE_TASK_STACK_WORDS];
static TaskHandle_t s_task_handle;
static bool s_worker_ready;

static void load_identity(void);
static void load_nickname(void);
static noise_session_t *find_session(uint16_t conn_handle);
static noise_session_t *alloc_session(uint16_t conn_handle);
static void clear_crypto(noise_session_t *session);
static void free_session(noise_session_t *session);
static NoiseHandshakeState *create_handshake(bool initiator);
static bool start_handshake(noise_session_t *session, const noise_event_t *evt);
static bool process_handshake(noise_session_t *session, const noise_event_t *evt);
static bool advance_handshake(noise_session_t *session);
static bool send_handshake_message(noise_session_t *session);
static bool derive_transport_keys(noise_session_t *session);
static void mark_established(noise_session_t *session);
static bool build_announce_payload(uint8_t *buffer, size_t buffer_len, size_t *out_len);
static size_t choose_padding_block(size_t payload_len);
static size_t apply_pkcs7_padding(uint8_t *buffer, size_t buffer_len, size_t current_len, size_t block_size);
static bool build_canonical_packet(const bitchat_packet_t *packet, uint8_t *out_buf, size_t *out_len, size_t max_len);
static bool build_identity_payload(uint8_t *buffer, size_t buffer_len, size_t *out_len);
static bool sign_packet(bitchat_packet_t *packet);
static bool parse_identity_payload(const uint8_t *p, size_t len, noise_identity_t *record);
static bool parse_announce_tlv(const uint8_t *payload, size_t len, noise_identity_t *record);
static bool encrypt_payload(noise_session_t *session, const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len);
static bool decrypt_payload(noise_session_t *session, const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len);
static void handle_noise_payload(uint16_t conn_handle, const noise_event_t *evt, noise_session_t *session, const uint8_t *decrypted, size_t decrypted_len);
static void format_hex(const uint8_t *data, size_t len, char *out, size_t out_len);
static bool send_identity_announce(noise_session_t *session);
static void process_announce_event(const noise_event_t *evt);
static void process_identity_event(const noise_event_t *evt);
static void process_encrypted_event(const noise_event_t *evt);
static void process_subscribed_event(const noise_event_t *evt);
static bool send_announce(noise_session_t *session);
static esp_err_t encode_and_send(uint16_t conn_handle, bitchat_message_type_t type, const uint8_t *recipient_id, const uint8_t *payload, size_t payload_len, bool sign);
static esp_err_t queue_event(const noise_event_t *evt, TickType_t wait_ticks);
static bool enqueue_event(noise_evt_type_t type, uint16_t conn_handle, const uint8_t peer_id[8], bool initiator, const uint8_t *payload, uint16_t payload_len);
static void handshake_task(void *arg);
static bool init_worker(void);
static void poll_session_maintenance(void);
static bool try_send_identity(noise_session_t *session);

static void load_identity(void)
{
    nvs_handle_t handle;
    if (nvs_open(NOISE_STATIC_KEY_NS, NVS_READWRITE, &handle) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS namespace");
        return;
    }

    size_t len = sizeof(s_static_private);
    if (nvs_get_blob(handle, NOISE_STATIC_KEY_KEY, s_static_private, &len) != ESP_OK || len != sizeof(s_static_private)) {
        ESP_LOGI(TAG, "Generating new static key");
        esp_fill_random(s_static_private, sizeof(s_static_private));
        ESP_ERROR_CHECK(nvs_set_blob(handle, NOISE_STATIC_KEY_KEY, s_static_private, sizeof(s_static_private)));
    }

    NoiseDHState *dh = NULL;
    if (noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519) == NOISE_ERROR_NONE) {
        if (noise_dhstate_set_keypair_private(dh, s_static_private, sizeof(s_static_private)) == NOISE_ERROR_NONE) {
            size_t pub_len = noise_dhstate_get_public_key_length(dh);
            if (pub_len == sizeof(s_static_public) && noise_dhstate_get_public_key(dh, s_static_public, pub_len) == NOISE_ERROR_NONE) {
                uint8_t hash[32];
                mbedtls_sha256(s_static_public, sizeof(s_static_public), hash, 0);
                memcpy(s_peer_id, hash, sizeof(s_peer_id));
                nvs_set_blob(handle, NOISE_PEER_ID_KEY, s_peer_id, sizeof(s_peer_id));
            }
        }
        noise_dhstate_free(dh);
    }

    len = sizeof(s_ed25519_private);
    if (nvs_get_blob(handle, NOISE_SIGN_PRIV_KEY, s_ed25519_private, &len) != ESP_OK || len != sizeof(s_ed25519_private)) {
        ESP_LOGI(TAG, "Generating new ed25519 key");
        esp_fill_random(s_ed25519_private, sizeof(s_ed25519_private));
        ESP_ERROR_CHECK(nvs_set_blob(handle, NOISE_SIGN_PRIV_KEY, s_ed25519_private, sizeof(s_ed25519_private)));
    }

    ed25519_publickey(s_ed25519_private, s_ed25519_public);
    nvs_set_blob(handle, NOISE_SIGN_PUB_KEY, s_ed25519_public, sizeof(s_ed25519_public));
    nvs_commit(handle);
    nvs_close(handle);
}

static void load_nickname(void)
{
    if (nickname_init(s_nickname, sizeof(s_nickname)) != ESP_OK) {
        strlcpy(s_nickname, "anon0000", sizeof(s_nickname));
    }
}


static noise_session_t *find_session(uint16_t conn_handle)
{
    for (size_t i = 0; i < NOISE_MAX_SESSIONS; ++i) {
        if (s_sessions[i].in_use && s_sessions[i].conn_handle == conn_handle) {
            return &s_sessions[i];
        }
    }
    return NULL;
}

static noise_session_t *alloc_session(uint16_t conn_handle)
{
    noise_session_t *existing = find_session(conn_handle);
    if (existing) {
        return existing;
    }
    for (size_t i = 0; i < NOISE_MAX_SESSIONS; ++i) {
        if (!s_sessions[i].in_use) {
            memset(&s_sessions[i], 0, sizeof(s_sessions[i]));
            s_sessions[i].in_use = true;
            s_sessions[i].conn_handle = conn_handle;
            s_identity_pending[i] = false;
            return &s_sessions[i];
        }
    }
    return NULL;
}

static void clear_crypto(noise_session_t *session)
{
    if (!session) {
        return;
    }
    if (session->handshake) {
        noise_handshakestate_free(session->handshake);
        session->handshake = NULL;
    }
    if (session->tx_cipher) {
        noise_cipherstate_free(session->tx_cipher);
        session->tx_cipher = NULL;
    }
    if (session->rx_cipher) {
        noise_cipherstate_free(session->rx_cipher);
        session->rx_cipher = NULL;
    }
    memset(session->handshake_hash, 0, sizeof(session->handshake_hash));
    session->handshake_hash_len = 0;
}

static void free_session(noise_session_t *session)
{
    if (!session) {
        return;
    }
    size_t idx = session - s_sessions;
    if (idx < NOISE_MAX_SESSIONS) {
        s_identity_pending[idx] = false;
    }
    clear_crypto(session);
    memset(session->peer_id, 0, sizeof(session->peer_id));
    session->initiator = false;
    session->established = false;
    session->identity_sent = false;
    session->sent_sync_gen = 0;
    session->in_use = false;
    if (idx < NOISE_MAX_SESSIONS) {
        memset(&s_identities[idx], 0, sizeof(s_identities[idx]));
    }
}

static NoiseHandshakeState *create_handshake(bool initiator)
{
    NoiseProtocolId id;
    int err = noise_protocol_name_to_id(&id, NOISE_PROTOCOL_NAME, strlen(NOISE_PROTOCOL_NAME));
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGE(TAG, "protocol_name_to_id failed err=%d", err);
        return NULL;
    }
    NoiseHandshakeState *state = NULL;
    int role = initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER;
    err = noise_handshakestate_new_by_id(&state, &id, role);
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGE(TAG, "handshakestate_new_by_id failed role=%d err=%d", role, err);
        return NULL;
    }
    // No prologue per reference implementation
    NoiseDHState *local = noise_handshakestate_get_local_keypair_dh(state);
    if (!local) {
        ESP_LOGE(TAG, "get_local_keypair_dh returned NULL");
        noise_handshakestate_free(state);
        return NULL;
    }
    err = noise_dhstate_set_keypair(local,
                                    s_static_private, sizeof(s_static_private),
                                    s_static_public, sizeof(s_static_public));
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGE(TAG, "dhstate_set_keypair failed err=%d", err);
        noise_handshakestate_free(state);
        return NULL;
    }
    return state;
}

static bool start_handshake(noise_session_t *session, const noise_event_t *evt)
{
    if (session->handshake) {
        ESP_LOGI(TAG, "conn=%u start requested but handshake already exists", session->conn_handle);
        return true;
    }
    session->handshake = create_handshake(evt->initiator);
    if (!session->handshake) {
        ESP_LOGW(TAG, "conn=%u create_handshake failed", session->conn_handle);
        return false;
    }
    session->initiator = evt->initiator;
    int err = noise_handshakestate_start(session->handshake);
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGW(TAG, "noise_handshakestate_start failed conn=%u err=%d", session->conn_handle, err);
        clear_crypto(session);
        return false;
    }
    memcpy(session->peer_id, evt->peer_id, sizeof(session->peer_id));
    session->identity_sent = false;
    session->established = false;
    ESP_LOGI(TAG, "conn=%u handshake started, action=%d initiator=%d", session->conn_handle,
             noise_handshakestate_get_action(session->handshake), session->initiator);
    return advance_handshake(session);
}

static bool process_handshake(noise_session_t *session, const noise_event_t *evt)
{
    if (session->handshake && session->initiator && evt->payload_len == 32) {
        /* Simultaneous handshakes: a 32-byte message is a fresh initiation.
         * Mirror upstream and yield — drop our initiator state and respond
         * to the peer's initiation instead. */
        ESP_LOGI(TAG, "conn=%u handshake collision; yielding to peer initiation", session->conn_handle);
        clear_crypto(session);
        session->established = false;
    }
    if (!session->handshake) {
        if (!start_handshake(session, evt)) {
            ESP_LOGW(TAG, "conn=%u failed to start handshake", session->conn_handle);
            return false;
        }
    }

    if (!session->initiator && evt->payload_len == 0) {
        ESP_LOGW(TAG, "conn=%u responder received empty handshake payload", session->conn_handle);
        return false;
    }

    NoiseBuffer message;
    noise_buffer_set_input(message, (uint8_t *)evt->payload, evt->payload_len);
    ESP_LOGI(TAG, "conn=%u processing handshake payload len=%u", session->conn_handle, (unsigned)evt->payload_len);
    if (evt->payload_len) {
        ESP_LOG_BUFFER_HEXDUMP(TAG, evt->payload, evt->payload_len, ESP_LOG_INFO);
    }

    uint8_t response[NOISE_MESSAGE_MAX];
    NoiseBuffer response_buf;
    noise_buffer_set_output(response_buf, response, sizeof(response));

    int err = noise_handshakestate_read_message(session->handshake, &message, &response_buf);
    if (err != NOISE_ERROR_NONE) {
        /* The handshake state is not re-entrant after a failed read; the
         * session must be torn down and restarted. */
        ESP_LOGW(TAG, "noise_handshakestate_read_message(len=%u) failed conn=%u err=%d", (unsigned)evt->payload_len, session->conn_handle, err);
        return false;
    }

    if (response_buf.size > 0) {
        ESP_LOGD(TAG, "conn=%u sending handshake response size=%u", session->conn_handle, (unsigned)response_buf.size);
        const uint8_t *recipient = (session->peer_id[0] | session->peer_id[1] | session->peer_id[2] | session->peer_id[3] |
                                    session->peer_id[4] | session->peer_id[5] | session->peer_id[6] | session->peer_id[7]) ? session->peer_id : NULL;
        if (encode_and_send(session->conn_handle, BITCHAT_MSG_NOISE_HANDSHAKE, recipient, response_buf.data, response_buf.size, false) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send handshake response conn=%u", session->conn_handle);
            return false;
        }
    }

    return advance_handshake(session);
}

static bool advance_handshake(noise_session_t *session)
{
    if (!session->handshake) {
        return false;
    }
    while (true) {
        int action = noise_handshakestate_get_action(session->handshake);
        switch (action) {
        case NOISE_ACTION_WRITE_MESSAGE:
    if (!send_handshake_message(session)) {
                return false;
            }
            if (noise_handshakestate_get_action(session->handshake) == NOISE_ACTION_WRITE_MESSAGE) {
                ESP_LOGW(TAG, "conn=%u handshake write yielded no data; waiting", session->conn_handle);
                return true;
            }
            break;
        case NOISE_ACTION_SPLIT:
            if (!derive_transport_keys(session)) {
                return false;
            }
            mark_established(session);
            return true;
        case NOISE_ACTION_COMPLETE:
            return true;
        case NOISE_ACTION_FAILED:
            ESP_LOGE(TAG, "conn=%u handshake failed", session->conn_handle);
            return false;
        case NOISE_ACTION_NONE:
        case NOISE_ACTION_READ_MESSAGE:
            return true;
        default:
            ESP_LOGE(TAG, "conn=%u unexpected handshake action %d", session->conn_handle, action);
            return false;
        }
    }
}

static bool send_handshake_message(noise_session_t *session)
{
    uint8_t buffer[NOISE_MESSAGE_MAX];
    NoiseBuffer msg;
    noise_buffer_set_output(msg, buffer, sizeof(buffer));
    int err = noise_handshakestate_write_message(session->handshake, &msg, NULL);
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGW(TAG, "noise_handshakestate_write_message failed conn=%u err=%d", session->conn_handle, err);
        return false;
    }
    if (msg.size == 0) {
        ESP_LOGD(TAG, "conn=%u write_message produced empty buffer", session->conn_handle);
        return true;
    }
    ESP_LOGD(TAG, "conn=%u noise_handshakestate_write_message size=%u", session->conn_handle, (unsigned)msg.size);
    /* Handshake packets are directed whenever the peer is known — both as
     * initiator and as responder; iOS ignores undirected handshakes. */
    const bool peer_known = (session->peer_id[0] | session->peer_id[1] | session->peer_id[2] | session->peer_id[3] |
                             session->peer_id[4] | session->peer_id[5] | session->peer_id[6] | session->peer_id[7]) != 0;
    const uint8_t *recipient = peer_known ? session->peer_id : NULL;

    return encode_and_send(session->conn_handle, BITCHAT_MSG_NOISE_HANDSHAKE, recipient, msg.data, msg.size, false) == ESP_OK;
}

static bool derive_transport_keys(noise_session_t *session)
{
    NoiseCipherState *tx = NULL;
    NoiseCipherState *rx = NULL;
    int err = noise_handshakestate_split(session->handshake, &tx, &rx);
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGE(TAG, "handshakestate_split failed conn=%u err=%d", session->conn_handle, err);
        return false;
    }
    session->tx_cipher = tx;
    session->rx_cipher = rx;
    session->tx_nonce = 0;
    session->handshake_hash_len = noise_handshakestate_get_handshake_hash(session->handshake, session->handshake_hash, sizeof(session->handshake_hash));
    session->established = true;
    ESP_LOGI(TAG, "Handshake split complete conn=%u", session->conn_handle);
    return true;
}

static void mark_established(noise_session_t *session)
{
    ESP_LOGI(TAG, "Handshake complete on conn=%u", session->conn_handle);
    noise_handshakestate_free(session->handshake);
    session->handshake = NULL;
    session->established = true;
    session->identity_sent = false;
    size_t idx = session - s_sessions;
    if (idx < NOISE_MAX_SESSIONS) {
        s_identity_pending[idx] = true;
    }
    if (try_send_identity(session)) {
        ESP_LOGI(TAG, "conn=%u identity sent immediately after handshake", session->conn_handle);
    }
}

/* Mirrors upstream MessagePadding.optimalBlockSize: smallest standard block
 * that fits the data plus 16 bytes of assumed overhead; 0 means "no padding"
 * (upstream leaves oversized packets unpadded). */
static size_t choose_padding_block(size_t payload_len)
{
    static const size_t blocks[] = {256, 512, 1024, 2048};
    for (size_t i = 0; i < sizeof(blocks) / sizeof(blocks[0]); ++i) {
        if (payload_len + 16 <= blocks[i]) {
            return blocks[i];
        }
    }
    return 0;
}

/* Mirrors upstream MessagePadding.pad: pad to exactly block_size with PKCS#7
 * bytes; a pad run longer than 255 cannot be encoded, so upstream signs those
 * packets unpadded and we must do the same. */
static size_t apply_pkcs7_padding(uint8_t *buffer, size_t buffer_len, size_t current_len, size_t block_size)
{
    if (block_size == 0 || current_len >= block_size || block_size > buffer_len) {
        return current_len;
    }
    size_t pad_len = block_size - current_len;
    if (pad_len > 255) {
        return current_len;
    }
    memset(buffer + current_len, (uint8_t)pad_len, pad_len);
    return current_len + pad_len;
}

static bool build_identity_payload(uint8_t *buffer, size_t buffer_len, size_t *out_len)
{
    size_t nickname_len = strnlen(s_nickname, sizeof(s_nickname));
    if (nickname_len > 255) {
        nickname_len = 255;
    }

    const size_t required = 1 + sizeof(s_peer_id) + 1 + sizeof(s_static_public) + 1 + sizeof(s_ed25519_public)
                            + 1 + nickname_len + 1 + 8 + 1 + 64;
    if (buffer_len < required) {
        ESP_LOGW(TAG, "Identity payload buffer too small");
        return false;
    }

    uint64_t timestamp_ms = bitchat_time_now_ms();

    size_t offset = 0;
    buffer[offset++] = 0x00; // flags

    memcpy(buffer + offset, s_peer_id, sizeof(s_peer_id));
    offset += sizeof(s_peer_id);

    buffer[offset++] = sizeof(s_static_public);
    memcpy(buffer + offset, s_static_public, sizeof(s_static_public));
    offset += sizeof(s_static_public);

    buffer[offset++] = sizeof(s_ed25519_public);
    memcpy(buffer + offset, s_ed25519_public, sizeof(s_ed25519_public));
    offset += sizeof(s_ed25519_public);

    buffer[offset++] = (uint8_t)nickname_len;
    memcpy(buffer + offset, s_nickname, nickname_len);
    offset += nickname_len;

    buffer[offset++] = 0x00; // previousPeerID length

    for (int i = 7; i >= 0; --i) {
        buffer[offset++] = (timestamp_ms >> (i * 8)) & 0xFF;
    }

    char peer_hex[sizeof(s_peer_id) * 2 + 1];
    for (size_t i = 0; i < sizeof(s_peer_id); ++i) {
        snprintf(peer_hex + i * 2, sizeof(peer_hex) - i * 2, "%02x", s_peer_id[i]);
    }

    char static_hex[sizeof(s_static_public) * 2 + 1];
    for (size_t i = 0; i < sizeof(s_static_public); ++i) {
        snprintf(static_hex + i * 2, sizeof(static_hex) - i * 2, "%02x", s_static_public[i]);
    }

    char timestamp_str[32];
    int ts_len = snprintf(timestamp_str, sizeof(timestamp_str), "%llu", (unsigned long long)timestamp_ms);
    if (ts_len < 0) {
        return false;
    }

    uint8_t binding[256];
    size_t binding_len = 0;
    const char *prefix = IDENTITY_BINDING_PREFIX;
    size_t prefix_len = strlen(prefix);
    memcpy(binding + binding_len, prefix, prefix_len);
    binding_len += prefix_len;
    memcpy(binding + binding_len, peer_hex, strlen(peer_hex));
    binding_len += strlen(peer_hex);
    memcpy(binding + binding_len, static_hex, strlen(static_hex));
    binding_len += strlen(static_hex);
    memcpy(binding + binding_len, timestamp_str, ts_len);
    binding_len += ts_len;

    uint8_t signature[64];
    ed25519_sign(binding, binding_len, s_ed25519_private, s_ed25519_public, signature);

    buffer[offset++] = sizeof(signature);
    memcpy(buffer + offset, signature, sizeof(signature));
    offset += sizeof(signature);

    *out_len = offset;
    return true;
}

static bool build_announce_payload(uint8_t *buffer, size_t buffer_len, size_t *out_len)
{
    size_t nickname_len = strnlen(s_nickname, sizeof(s_nickname));
    if (nickname_len > 255) {
        nickname_len = 255;
    }

    size_t required = 2 + nickname_len + 2 + sizeof(s_static_public) + 2 + sizeof(s_ed25519_public);
    if (buffer_len < required) {
        ESP_LOGW(TAG, "ANNOUNCE payload buffer too small");
        return false;
    }

    size_t offset = 0;
    buffer[offset++] = 0x01;
    buffer[offset++] = (uint8_t)nickname_len;
    memcpy(buffer + offset, s_nickname, nickname_len);
    offset += nickname_len;

    buffer[offset++] = 0x02;
    buffer[offset++] = sizeof(s_static_public);
    memcpy(buffer + offset, s_static_public, sizeof(s_static_public));
    offset += sizeof(s_static_public);

    buffer[offset++] = 0x03;
    buffer[offset++] = sizeof(s_ed25519_public);
    memcpy(buffer + offset, s_ed25519_public, sizeof(s_ed25519_public));
    offset += sizeof(s_ed25519_public);

    /* Bitle-private firmware version TLV; unknown TLVs are skipped by the
     * phones' tolerant decoders, and other Bitle nodes use it to decide
     * whether to offer an OTA image. */
    buffer[offset++] = 0xB0;
    buffer[offset++] = 4;
    buffer[offset++] = (BITLE_FW_VERSION >> 24) & 0xFF;
    buffer[offset++] = (BITLE_FW_VERSION >> 16) & 0xFF;
    buffer[offset++] = (BITLE_FW_VERSION >> 8) & 0xFF;
    buffer[offset++] = BITLE_FW_VERSION & 0xFF;

    *out_len = offset;
    return true;
}

static bool build_canonical_packet(const bitchat_packet_t *packet, uint8_t *out_buf, size_t *out_len, size_t max_len)
{
    if (!packet || !out_buf || !out_len) {
        return false;
    }

    uint8_t header[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t header_len = 0;

    header[header_len++] = packet->version;
    header[header_len++] = packet->type;
    header[header_len++] = 0; // TTL forced to zero

    for (int i = 7; i >= 0; --i) {
        header[header_len++] = (packet->timestamp_ms >> (i * 8)) & 0xFF;
    }

    uint8_t flags = 0;
    if (packet->has_recipient) {
        flags |= 0x01;
    }
    header[header_len++] = flags;

    header[header_len++] = (packet->payload_len >> 8) & 0xFF;
    header[header_len++] = packet->payload_len & 0xFF;

    memcpy(header + header_len, packet->sender_id, sizeof(packet->sender_id));
    header_len += sizeof(packet->sender_id);

    if (packet->has_recipient) {
        memcpy(header + header_len, packet->recipient_id, sizeof(packet->recipient_id));
        header_len += sizeof(packet->recipient_id);
    }

    if (header_len + packet->payload_len > max_len) {
        return false;
    }

    memcpy(out_buf, header, header_len);
    memcpy(out_buf + header_len, packet->payload, packet->payload_len);

    size_t total_len = header_len + packet->payload_len;
    size_t block_size = choose_padding_block(total_len);
    total_len = apply_pkcs7_padding(out_buf, max_len, total_len, block_size);

    *out_len = total_len;
    return true;
}

static bool sign_packet(bitchat_packet_t *packet)
{
    uint8_t buffer[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t canonical_len = 0;
    if (!build_canonical_packet(packet, buffer, &canonical_len, sizeof(buffer))) {
        ESP_LOGW(TAG, "Canonical encode failed for type=0x%02X", packet->type);
        return false;
    }
    ed25519_sign(buffer, canonical_len, s_ed25519_private, s_ed25519_public, packet->signature);
    packet->has_signature = true;
    return true;
}

static bool send_identity_announce(noise_session_t *session)
{
    if (!bitchat_time_is_valid()) {
        ESP_LOGI(TAG, "conn=%u postponing identity announce until time is valid", session->conn_handle);
        return false;
    }

    uint8_t payload[NOISE_MESSAGE_MAX];
    size_t payload_len = 0;
    if (!build_identity_payload(payload, sizeof(payload), &payload_len)) {
        ESP_LOGW(TAG, "Failed to build identity payload");
        return false;
    }
    if (encode_and_send(session->conn_handle, BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE, NULL, payload, payload_len, true) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to send identity announce; will retry later");
        return false;
    }
    ESP_LOGI(TAG, "conn=%u sent IDENTITY_ANNOUNCE (%u bytes)", session->conn_handle, (unsigned)payload_len);
    return true;
}

static bool try_send_identity(noise_session_t *session)
{
    if (!session) {
        return false;
    }
    size_t idx = session - s_sessions;
    if (idx >= NOISE_MAX_SESSIONS) {
        return false;
    }
    if (!s_identity_pending[idx]) {
        return false;
    }
    if (session->identity_sent) {
        return true;
    }
    if (!bitchat_ble_conn_subscribed(session->conn_handle)) {
        /* Link cannot carry notifications yet; the subscribe event or the
         * BLE watchdog will get us unstuck — stay quiet until then. */
        return false;
    }
    if (!bitchat_time_is_valid()) {
        ESP_LOGI(TAG, "conn=%u deferring identity; time not valid", session->conn_handle);
        return false;
    }
    /* The signed ANNOUNCE is what current clients require before they will
     * talk to us (identity rides in its TLVs), so it gates success; the
     * legacy 0x13 identity announce is best-effort for older clients. */
    if (!send_announce(session)) {
        ESP_LOGW(TAG, "Failed to send ANNOUNCE conn=%u; will retry", session->conn_handle);
        return false;
    }
    if (!send_identity_announce(session)) {
        ESP_LOGD(TAG, "Legacy identity announce skipped conn=%u", session->conn_handle);
    }
    s_identity_pending[idx] = false;
    session->identity_sent = true;
    session->sent_sync_gen = bitchat_time_sync_generation();
    ESP_LOGI(TAG, "conn=%u identity and announce sent", session->conn_handle);
    return true;
}

static bool send_announce(noise_session_t *session)
{
    if (!session) {
        return false;
    }

    if (!bitchat_time_is_valid()) {
        ESP_LOGI(TAG, "conn=%u postponing ANNOUNCE until time is valid", session->conn_handle);
        return false;
    }

    uint8_t announce_payload[128];
    size_t announce_len = 0;
    if (!build_announce_payload(announce_payload, sizeof(announce_payload), &announce_len)) {
        ESP_LOGW(TAG, "Failed to build ANNOUNCE payload");
        return false;
    }
    bitchat_packet_t packet = {0};
    packet.version = 1;
    packet.type = BITCHAT_MSG_ANNOUNCE;
    packet.ttl = NOISE_PACKET_TTL;
    packet.timestamp_ms = bitchat_time_now_ms();
    memcpy(packet.sender_id, s_peer_id, sizeof(packet.sender_id));
    packet.payload = announce_payload;
    packet.payload_len = announce_len;

    if (!sign_packet(&packet)) {
        ESP_LOGW(TAG, "Failed to sign ANNOUNCE packet");
        return false;
    }

    uint8_t buffer[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t encoded_len = sizeof(buffer);
    if (!bitchat_packet_encode(&packet, buffer, &encoded_len, sizeof(buffer))) {
        ESP_LOGW(TAG, "Failed to encode ANNOUNCE packet");
        return false;
    }

    if (bitchat_ble_send(session->conn_handle, buffer, encoded_len) != ESP_OK) {
        return false;
    }

    session->last_announce_ms = esp_timer_get_time() / 1000ULL;
    ESP_LOGI(TAG, "conn=%u sent ANNOUNCE (%u bytes)", session->conn_handle, (unsigned)announce_len);
    return true;
}

static bool parse_identity_payload(const uint8_t *p, size_t len, noise_identity_t *record)
{
    if (!record || !p || len < 1) {
        return false;
    }
    size_t offset = 0;

    if (offset + 1 + sizeof(record->peer_id) > len) {
        return false;
    }
    uint8_t flags = p[offset++];
    (void)flags;

    memcpy(record->peer_id, p + offset, sizeof(record->peer_id));
    offset += sizeof(record->peer_id);

    if (offset >= len) {
        return false;
    }
    uint8_t static_len = p[offset++];
    if (offset + static_len > len) {
        return false;
    }
    offset += static_len;

    if (offset >= len) {
        return false;
    }
    uint8_t sign_len = p[offset++];
    if (offset + sign_len > len) {
        return false;
    }
    offset += sign_len;

    if (offset >= len) {
        return false;
    }
    uint8_t nick_len = p[offset++];
    if (nick_len == 0 || nick_len >= sizeof(record->nickname) || offset + nick_len > len) {
        return false;
    }
    memcpy(record->nickname, p + offset, nick_len);
    record->nickname[nick_len] = '\0';
    record->nickname_len = nick_len;
    offset += nick_len;

    if (offset >= len) {
        return false;
    }
    uint8_t previous_len = p[offset++];
    if (offset + previous_len > len) {
        return false;
    }
    offset += previous_len;

    if (offset + 8 > len) {
        return false;
    }
    uint64_t timestamp = 0;
    for (int i = 0; i < 8; ++i) {
        timestamp = (timestamp << 8) | p[offset++];
    }

    if (offset >= len) {
        return false;
    }
    uint8_t sig_len = p[offset++];
    if (offset + sig_len > len) {
        return false;
    }
    offset += sig_len;

    record->timestamp_ms = timestamp;
    record->valid = true;
    bitchat_time_consider_peer(timestamp);
    return true;
}

/* Parses the current-protocol ANNOUNCE TLV payload: 0x01 nickname,
 * 0x02 Noise static key, 0x03 Ed25519 signing key; unknown TLVs are
 * skipped for forward compatibility (mirrors AnnouncementPacket.decode). */
static bool parse_announce_tlv(const uint8_t *payload, size_t len, noise_identity_t *record)
{
    if (!payload || !record) {
        return false;
    }
    bool have_nick = false;
    bool have_noise = false;
    bool have_sign = false;
    size_t offset = 0;
    while (offset + 2 <= len) {
        uint8_t tlv_type = payload[offset++];
        uint8_t tlv_len = payload[offset++];
        if (offset + tlv_len > len) {
            return false;
        }
        const uint8_t *value = payload + offset;
        offset += tlv_len;
        switch (tlv_type) {
        case 0x01: {
            if (tlv_len == 0) {
                return false;
            }
            uint8_t copy_len = tlv_len < sizeof(record->nickname) - 1 ? tlv_len : (uint8_t)(sizeof(record->nickname) - 1);
            memcpy(record->nickname, value, copy_len);
            record->nickname[copy_len] = '\0';
            record->nickname_len = copy_len;
            have_nick = true;
            break;
        }
        case 0x02:
            if (tlv_len != sizeof(record->noise_key)) {
                return false;
            }
            memcpy(record->noise_key, value, tlv_len);
            have_noise = true;
            break;
        case 0x03:
            if (tlv_len != sizeof(record->sign_key)) {
                return false;
            }
            memcpy(record->sign_key, value, tlv_len);
            have_sign = true;
            break;
        case 0xB0:
            if (tlv_len == 4) {
                record->fw_version = ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
                                     ((uint32_t)value[2] << 8) | value[3];
            }
            break;
        default:
            break;
        }
    }
    return have_nick && have_noise && have_sign;
}

/* Returns false when the sender ID is not derived from the announced Noise
 * key (spoofed announce, hard reject). Sets *out_sig_ok when the packet
 * signature verifies against the announced signing key. */
static bool verify_announce_event(const noise_event_t *evt, const noise_identity_t *record, bool *out_sig_ok)
{
    *out_sig_ok = false;
    uint8_t hash[32];
    mbedtls_sha256(record->noise_key, sizeof(record->noise_key), hash, 0);
    if (memcmp(hash, evt->peer_id, sizeof(evt->peer_id)) != 0) {
        return false;
    }
    if (!evt->has_signature) {
        return true;
    }
    bitchat_packet_t packet = {0};
    packet.version = 1;
    packet.type = BITCHAT_MSG_ANNOUNCE;
    packet.timestamp_ms = evt->timestamp_ms;
    memcpy(packet.sender_id, evt->peer_id, sizeof(packet.sender_id));
    packet.payload = (uint8_t *)evt->payload;
    packet.payload_len = evt->payload_len;

    uint8_t canonical[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t canonical_len = 0;
    if (build_canonical_packet(&packet, canonical, &canonical_len, sizeof(canonical))) {
        *out_sig_ok = ed25519_sign_open(canonical, canonical_len,
                                        (unsigned char *)record->sign_key,
                                        (unsigned char *)evt->signature) == 0;
    }
    return true;
}

/* BitChat transport payloads carry an explicit nonce (NoiseCipherState with
 * useExtractedNonce=true): <4-byte BE nonce><ciphertext><16-byte tag>. */
#define NOISE_TRANSPORT_NONCE_LEN 4

static bool encrypt_payload(noise_session_t *session, const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len)
{
    if (!session || !session->tx_cipher || !output || !output_len ||
        input_len + NOISE_TRANSPORT_NONCE_LEN > *output_len) {
        return false;
    }
    uint32_t nonce = session->tx_nonce;
    output[0] = (nonce >> 24) & 0xFF;
    output[1] = (nonce >> 16) & 0xFF;
    output[2] = (nonce >> 8) & 0xFF;
    output[3] = nonce & 0xFF;
    memcpy(output + NOISE_TRANSPORT_NONCE_LEN, input, input_len);
    if (noise_cipherstate_set_nonce(session->tx_cipher, nonce) != NOISE_ERROR_NONE) {
        return false;
    }
    NoiseBuffer buffer;
    noise_buffer_set_inout(buffer, output + NOISE_TRANSPORT_NONCE_LEN, input_len,
                           *output_len - NOISE_TRANSPORT_NONCE_LEN);
    if (noise_cipherstate_encrypt(session->tx_cipher, &buffer) != NOISE_ERROR_NONE) {
        return false;
    }
    session->tx_nonce = nonce + 1;
    *output_len = buffer.size + NOISE_TRANSPORT_NONCE_LEN;
    return true;
}

static bool decrypt_payload(noise_session_t *session, const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len)
{
    if (!session || !session->rx_cipher || !output || !output_len ||
        input_len <= NOISE_TRANSPORT_NONCE_LEN ||
        input_len - NOISE_TRANSPORT_NONCE_LEN > *output_len) {
        return false;
    }
    uint32_t nonce = ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
                     ((uint32_t)input[2] << 8) | (uint32_t)input[3];
    /* noise-c refuses backward nonces, which doubles as replay protection. */
    if (noise_cipherstate_set_nonce(session->rx_cipher, nonce) != NOISE_ERROR_NONE) {
        ESP_LOGW(TAG, "conn=%u rejected transport nonce %u (replay?)", session->conn_handle, (unsigned)nonce);
        return false;
    }
    memcpy(output, input + NOISE_TRANSPORT_NONCE_LEN, input_len - NOISE_TRANSPORT_NONCE_LEN);
    NoiseBuffer buffer;
    noise_buffer_set_inout(buffer, output, input_len - NOISE_TRANSPORT_NONCE_LEN, *output_len);
    if (noise_cipherstate_decrypt(session->rx_cipher, &buffer) != NOISE_ERROR_NONE) {
        return false;
    }
    *output_len = buffer.size;
    return true;
}

/* Random v4 UUID formatted like Foundation's UUID().uuidString. */
static void generate_uuid_string(char *out, size_t out_len)
{
    uint8_t raw[16];
    esp_fill_random(raw, sizeof(raw));
    raw[6] = (raw[6] & 0x0F) | 0x40;
    raw[8] = (raw[8] & 0x3F) | 0x80;
    snprintf(out, out_len,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
             raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
}

static void send_auto_reply(noise_session_t *session)
{
    const char *text = BITLE_AUTO_REPLY_TEXT;
    size_t text_len = strlen(text);
    char message_id[37];
    generate_uuid_string(message_id, sizeof(message_id));
    size_t id_len = strlen(message_id);

    /* PrivateMessagePacket TLVs: 0x00 messageID, 0x01 content. */
    uint8_t payload[2 + sizeof(message_id) + 2 + sizeof(BITLE_AUTO_REPLY_TEXT)];
    size_t offset = 0;
    payload[offset++] = 0x00;
    payload[offset++] = (uint8_t)id_len;
    memcpy(payload + offset, message_id, id_len);
    offset += id_len;
    payload[offset++] = 0x01;
    payload[offset++] = (uint8_t)text_len;
    memcpy(payload + offset, text, text_len);
    offset += text_len;

    if (noise_send_encrypted(session->conn_handle, BITCHAT_NOISE_PAYLOAD_PRIVATE_MESSAGE, payload, offset)) {
        session->auto_replied = true;
        ESP_LOGI(TAG, "conn=%u auto-reply sent", session->conn_handle);
    } else {
        ESP_LOGW(TAG, "conn=%u auto-reply send failed", session->conn_handle);
    }
}

static void handle_noise_payload(uint16_t conn_handle, const noise_event_t *evt, noise_session_t *session, const uint8_t *decrypted, size_t decrypted_len)
{
    (void)evt;
    if (!decrypted || decrypted_len == 0) {
        ESP_LOGW(TAG, "Encrypted payload from conn=%u is empty", conn_handle);
        return;
    }
    uint8_t payload_type = decrypted[0];
    ESP_LOGI(TAG, "Encrypted payload type=0x%02X len=%u", payload_type, (unsigned)(decrypted_len - 1));
    if (payload_type != BITCHAT_NOISE_PAYLOAD_PRIVATE_MESSAGE) {
        return;
    }

    /* PrivateMessagePacket TLVs: 0x00 messageID, 0x01 content. */
    const uint8_t *p = decrypted + 1;
    size_t len = decrypted_len - 1;
    size_t offset = 0;
    char message_id[64] = {0};
    while (offset + 2 <= len) {
        uint8_t tlv_type = p[offset++];
        uint8_t tlv_len = p[offset++];
        if (offset + tlv_len > len) {
            break;
        }
        if (tlv_type == 0x00 && tlv_len < sizeof(message_id)) {
            memcpy(message_id, p + offset, tlv_len);
            message_id[tlv_len] = '\0';
        } else if (tlv_type == 0x01) {
            char content[256];
            size_t copy_len = tlv_len < sizeof(content) - 1 ? tlv_len : sizeof(content) - 1;
            memcpy(content, p + offset, copy_len);
            content[copy_len] = '\0';
            ESP_LOGI(TAG, "PRIVATE message on conn=%u: %s", conn_handle, content);
        }
        offset += tlv_len;
    }

    /* Delivery ack (payload = raw messageID string) puts the checkmark on
     * the sender's phone. */
    if (message_id[0] != '\0') {
        if (!noise_send_encrypted(conn_handle, BITCHAT_NOISE_PAYLOAD_DELIVERED,
                                  (const uint8_t *)message_id, strlen(message_id))) {
            ESP_LOGW(TAG, "conn=%u delivery ack failed", conn_handle);
        }
    }

    /* One informational auto-reply per session, so a chatty sender (or
     * another bot) cannot ping-pong with us. */
    if (session && !session->auto_replied) {
        send_auto_reply(session);
    }
}

static void format_hex(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    if (!data || !out || out_len < len * 2 + 1) {
        if (out && out_len) {
            out[0] = '\0';
        }
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        snprintf(out + i * 2, out_len - i * 2, "%02X", data[i]);
    }
    out[len * 2] = '\0';
}

static esp_err_t encode_and_send(uint16_t conn_handle, bitchat_message_type_t type, const uint8_t *recipient_id, const uint8_t *payload, size_t payload_len, bool sign)
{
    bitchat_packet_t packet;
    memset(&packet, 0, sizeof(packet));
    packet.version = 1;
    packet.type = type;
    /* Every packet needs a live timestamp: iOS validates ±120 s of skew on
     * all inbound packets, handshakes included. */
    packet.ttl = NOISE_PACKET_TTL;
    packet.timestamp_ms = bitchat_time_now_ms();
    if (!packet.timestamp_ms) {
        ESP_LOGW(TAG, "Skipping send; timestamp invalid for type=0x%02X", type);
        return ESP_ERR_INVALID_STATE;
    }
    memcpy(packet.sender_id, s_peer_id, sizeof(packet.sender_id));
    if (recipient_id) {
        memcpy(packet.recipient_id, recipient_id, sizeof(packet.recipient_id));
        packet.has_recipient = true;
    }
    packet.payload = (uint8_t *)payload;
    packet.payload_len = payload_len;
    packet.has_signature = false;

    if (sign && !sign_packet(&packet)) {
        ESP_LOGW(TAG, "Failed to sign packet type=0x%02X", type);
    }

    uint8_t buffer[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t encoded_len = sizeof(buffer);
    if (!bitchat_packet_encode(&packet, buffer, &encoded_len, sizeof(buffer))) {
        ESP_LOGE(TAG, "Failed to encode packet type=0x%02X", type);
        return ESP_FAIL;
    }

    return bitchat_ble_send(conn_handle, buffer, encoded_len);
}

static esp_err_t queue_event(const noise_event_t *evt, TickType_t wait_ticks)
{
    if (!s_event_queue) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xQueueSend(s_event_queue, evt, wait_ticks) != pdTRUE) {
        ESP_LOGW(TAG, "Event queue full; dropping type=%d conn=%u", evt->type, evt->conn_handle);
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

static bool enqueue_event(noise_evt_type_t type, uint16_t conn_handle, const uint8_t peer_id[8], bool initiator, const uint8_t *payload, uint16_t payload_len)
{
    if (!init_worker()) {
        return false;
    }
    if (payload_len > NOISE_EVENT_PAYLOAD_MAX) {
        ESP_LOGW(TAG, "Dropping event type=%d payload too large (%u)", type, payload_len);
        return false;
    }
    noise_event_t evt = {
        .type = type,
        .conn_handle = conn_handle,
        .initiator = initiator,
        .payload_len = payload_len,
    };
    if (peer_id) {
        memcpy(evt.peer_id, peer_id, sizeof(evt.peer_id));
    }
    if (payload && payload_len) {
        memcpy(evt.payload, payload, payload_len);
    }
    return queue_event(&evt, 0) == ESP_OK;
}

/* Copies the fields the worker needs from a decoded packet, including the
 * pieces required to re-verify the packet signature off the host task. */
static bool enqueue_packet_event(noise_evt_type_t type, uint16_t conn_handle, const bitchat_packet_t *packet)
{
    if (!init_worker()) {
        return false;
    }
    if (packet->payload_len > NOISE_EVENT_PAYLOAD_MAX) {
        ESP_LOGW(TAG, "Dropping type=0x%02X payload too large (%u)", packet->type, packet->payload_len);
        return false;
    }
    noise_event_t evt = {
        .type = type,
        .conn_handle = conn_handle,
        .timestamp_ms = packet->timestamp_ms,
        .ttl = packet->ttl,
        .has_signature = packet->has_signature,
        .payload_len = packet->payload_len,
    };
    memcpy(evt.peer_id, packet->sender_id, sizeof(evt.peer_id));
    if (packet->has_signature) {
        memcpy(evt.signature, packet->signature, sizeof(evt.signature));
    }
    if (packet->payload && packet->payload_len) {
        memcpy(evt.payload, packet->payload, packet->payload_len);
    }
    return queue_event(&evt, 0) == ESP_OK;
}

static void handshake_task(void *arg)
{
    (void)arg;
    noise_event_t evt;
    while (true) {
        /* All session state is owned by this task; the timeout keeps the
         * periodic maintenance running even when no packets arrive. */
        if (xQueueReceive(s_event_queue, &evt, pdMS_TO_TICKS(500)) == pdTRUE) {
            switch (evt.type) {
            case NOISE_EVT_START: {
                noise_session_t *session = alloc_session(evt.conn_handle);
                if (!session) {
                    ESP_LOGW(TAG, "No free session slots for conn=%u", evt.conn_handle);
                    break;
                }
                if (session->handshake) {
                    ESP_LOGI(TAG, "conn=%u handshake already active", evt.conn_handle);
                    break;
                }
                if (!start_handshake(session, &evt)) {
                    ESP_LOGW(TAG, "Handshake start failed for conn=%u", evt.conn_handle);
                    free_session(session);
                }
                break;
            }
            case NOISE_EVT_PROCESS: {
                noise_session_t *session = find_session(evt.conn_handle);
                if (!session) {
                    session = alloc_session(evt.conn_handle);
                    if (!session) {
                        ESP_LOGW(TAG, "No session available for incoming handshake conn=%u", evt.conn_handle);
                        break;
                    }
                }
                memcpy(session->peer_id, evt.peer_id, sizeof(session->peer_id));
                if (!process_handshake(session, &evt)) {
                    ESP_LOGW(TAG, "Handshake processing failed for conn=%u", evt.conn_handle);
                    free_session(session);
                }
                break;
            }
            case NOISE_EVT_ANNOUNCE:
                process_announce_event(&evt);
                break;
            case NOISE_EVT_IDENTITY:
                process_identity_event(&evt);
                break;
            case NOISE_EVT_ENCRYPTED:
                process_encrypted_event(&evt);
                break;
            case NOISE_EVT_SUBSCRIBED:
                process_subscribed_event(&evt);
                break;
            case NOISE_EVT_DISCONNECT: {
                noise_session_t *session = find_session(evt.conn_handle);
                if (session) {
                    ESP_LOGI(TAG, "Resetting session conn=%u", evt.conn_handle);
                    free_session(session);
                }
                break;
            }
            default:
                break;
            }
        }
        poll_session_maintenance();
    }
}

static bool init_worker(void)
{
    if (s_worker_ready) {
        return true;
    }
    s_event_queue = xQueueCreateStatic(NOISE_QUEUE_DEPTH, sizeof(noise_event_t), s_queue_storage, &s_queue_struct);
    if (!s_event_queue) {
        ESP_LOGE(TAG, "Failed to create handshake queue");
        return false;
    }
    s_task_handle = xTaskCreateStatic(handshake_task, "noise_handshake", NOISE_HANDSHAKE_TASK_STACK_WORDS, NULL, NOISE_HANDSHAKE_TASK_PRIORITY, s_task_stack, &s_task_struct);
    if (!s_task_handle) {
        ESP_LOGE(TAG, "Failed to create handshake task");
        return false;
    }
    s_worker_ready = true;
    return true;
}

/* --- Host-task entry points: everything is marshalled onto the worker task
 * via the event queue so session state has a single owner. --- */

void noise_handle_handshake(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    enqueue_event(NOISE_EVT_PROCESS, conn_handle, packet->sender_id, false, packet->payload, packet->payload_len);
}

void noise_handle_identity_announce(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    enqueue_packet_event(NOISE_EVT_IDENTITY, conn_handle, packet);
}

void noise_handle_announce(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    enqueue_packet_event(NOISE_EVT_ANNOUNCE, conn_handle, packet);
}

void noise_handle_encrypted(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    enqueue_packet_event(NOISE_EVT_ENCRYPTED, conn_handle, packet);
}

void noise_notify_subscribed(uint16_t conn_handle)
{
    enqueue_event(NOISE_EVT_SUBSCRIBED, conn_handle, NULL, false, NULL, 0);
}

/* --- Worker-task processors --- */

static void process_announce_event(const noise_event_t *evt)
{
    uint16_t conn_handle = evt->conn_handle;
    /* Announces relayed from further hops share this link but describe other
     * peers; only direct announces (original TTL) identify the link peer. */
    bool is_direct = evt->ttl == NOISE_PACKET_TTL;
    noise_identity_t ident = {0};

    if (parse_announce_tlv(evt->payload, evt->payload_len, &ident)) {
        bool sig_ok = false;
        if (!verify_announce_event(evt, &ident, &sig_ok)) {
            ESP_LOGW(TAG, "conn=%u ANNOUNCE sender not derived from announced key; dropping", conn_handle);
            return;
        }
        if (evt->has_signature && !sig_ok) {
            /* Older clients sign with a different scheme; keep the peer but
             * leave it unverified rather than breaking interop. */
            ESP_LOGW(TAG, "conn=%u ANNOUNCE signature did not verify", conn_handle);
        }
        if (sig_ok) {
            /* End-to-end proof the radio + crypto of this image works;
             * lets a freshly OTA'd image cancel its rollback window. */
            bitle_ota_mark_healthy();
            bitle_ota_peer_version_seen(conn_handle, evt->peer_id, ident.fw_version);
        }
        if (is_direct) {
            noise_session_t *session = alloc_session(conn_handle);
            if (session) {
                size_t idx = session - s_sessions;
                ident.valid = true;
                ident.verified = sig_ok;
                ident.timestamp_ms = evt->timestamp_ms;
                memcpy(ident.peer_id, evt->peer_id, sizeof(ident.peer_id));
                if (!s_identities[idx].verified || sig_ok) {
                    s_identities[idx] = ident;
                }
                session->direct_peer = true;
                const uint8_t zero_id[8] = {0};
                if (memcmp(session->peer_id, zero_id, sizeof(zero_id)) == 0) {
                    memcpy(session->peer_id, evt->peer_id, sizeof(session->peer_id));
                }
                /* Two Bitles can dial each other simultaneously, wasting a
                 * slot on a duplicate link. The higher peer ID hangs up its
                 * own outbound leg, leaving exactly one link. */
                for (size_t i = 0; i < NOISE_MAX_SESSIONS; ++i) {
                    noise_session_t *other = &s_sessions[i];
                    if (other == session || !other->in_use ||
                        memcmp(other->peer_id, evt->peer_id, sizeof(other->peer_id)) != 0) {
                        continue;
                    }
                    if (memcmp(s_peer_id, evt->peer_id, sizeof(s_peer_id)) > 0) {
                        uint16_t victim = 0xFFFF;
                        if (bitchat_ble_conn_is_central(session->conn_handle)) {
                            victim = session->conn_handle;
                        } else if (bitchat_ble_conn_is_central(other->conn_handle)) {
                            victim = other->conn_handle;
                        }
                        if (victim != 0xFFFF) {
                            ESP_LOGI(TAG, "Duplicate link to peer; dropping our central conn=%u", victim);
                            bitchat_ble_disconnect(victim);
                        }
                    }
                    break;
                }
            }
        }
        ESP_LOGI(TAG, "conn=%u peer '%s' announced (%s%s)", conn_handle, ident.nickname,
                 sig_ok ? "verified" : "unverified", is_direct ? "" : ", relayed");
    } else {
        ESP_LOGW(TAG, "conn=%u ANNOUNCE TLV parse failed", conn_handle);
    }

    noise_session_t *session = find_session(conn_handle);
    if (session && !session->identity_sent) {
        size_t idx = session - s_sessions;
        s_identity_pending[idx] = true;
        try_send_identity(session);
    }
    /* Lazy handshake, like the mobile clients: never initiate a Noise
     * session on announce. Phones initiate when a private message needs
     * one; a relay pre-initiating leaves stuck pending sessions on the
     * peer and blocks their DM path. We answer as responder only. */
}

static void process_identity_event(const noise_event_t *evt)
{
    noise_session_t *session = alloc_session(evt->conn_handle);
    if (!session) {
        ESP_LOGW(TAG, "No session slot for identity announce conn=%u", evt->conn_handle);
        return;
    }
    size_t index = session - s_sessions;
    if (index >= NOISE_MAX_SESSIONS) {
        return;
    }
    noise_identity_t ident = {0};
    if (parse_identity_payload(evt->payload, evt->payload_len, &ident)) {
        ESP_LOGI(TAG, "Stored legacy identity for conn=%u", evt->conn_handle);
        if (!s_identities[index].verified) {
            memcpy(ident.peer_id, evt->peer_id, sizeof(ident.peer_id));
            s_identities[index] = ident;
        }
        const uint8_t zero_id[8] = {0};
        if (memcmp(session->peer_id, zero_id, sizeof(zero_id)) == 0) {
            /* Relayed identity announces can arrive for other peers in the
             * mesh; only bind the direct peer while it is still unknown. */
            memcpy(session->peer_id, evt->peer_id, sizeof(session->peer_id));
        }
        try_send_identity(session);
    }
}

static void process_encrypted_event(const noise_event_t *evt)
{
    noise_session_t *session = find_session(evt->conn_handle);
    if (!session || !session->established) {
        /* The peer kept a session across our reboot. Mirror the mobile
         * clients: initiate a fresh handshake so the link recovers. */
        ESP_LOGW(TAG, "Encrypted payload without session for conn=%u; re-handshaking", evt->conn_handle);
        if (!session || !session->handshake) {
            noise_begin_handshake(evt->conn_handle, evt->peer_id, NULL);
        }
        return;
    }
    uint8_t plaintext[NOISE_MAX_ENCRYPTED_PAYLOAD];
    size_t plaintext_len = sizeof(plaintext);
    if (!decrypt_payload(session, evt->payload, evt->payload_len, plaintext, &plaintext_len)) {
        ESP_LOGW(TAG, "Decrypt failed for conn=%u", evt->conn_handle);
        return;
    }
    handle_noise_payload(evt->conn_handle, evt, session, plaintext, plaintext_len);
}

static void process_subscribed_event(const noise_event_t *evt)
{
    noise_session_t *existing = find_session(evt->conn_handle);
    if (existing) {
        /* A fresh subscription means a fresh link; drop any state left over
         * from a previous connection that reused this handle. */
        free_session(existing);
    }
    noise_session_t *session = alloc_session(evt->conn_handle);
    if (!session) {
        ESP_LOGW(TAG, "No session slot for subscriber conn=%u", evt->conn_handle);
        return;
    }
    size_t idx = session - s_sessions;
    if (idx < NOISE_MAX_SESSIONS) {
        s_identity_pending[idx] = true;
    }
    /* Speak first: iOS stays silent toward peers it has not verified, so
     * first contact must come from us. */
    ESP_LOGI(TAG, "conn=%u subscribed; sending initial announce", evt->conn_handle);
    try_send_identity(session);
}

void noise_handle_public_message(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    (void)conn_handle;
    char peer_hex[17];
    format_hex(packet->sender_id, sizeof(packet->sender_id), peer_hex, sizeof(peer_hex));
    char buf[257];
    size_t copy_len = packet->payload_len < sizeof(buf) - 1 ? packet->payload_len : sizeof(buf) - 1;
    memcpy(buf, packet->payload, copy_len);
    buf[copy_len] = '\0';
    ESP_LOGI(TAG, "PLAIN message from %s: %s", peer_hex, buf);
}

void noise_reset_connection(uint16_t conn_handle)
{
    if (!init_worker()) {
        return;
    }
    noise_event_t evt = {
        .type = NOISE_EVT_DISCONNECT,
        .conn_handle = conn_handle,
    };
    /* Wait briefly rather than drop: a lost disconnect would leak the
     * session slot until the conn handle is reused. */
    if (queue_event(&evt, pdMS_TO_TICKS(100)) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to queue disconnect for conn=%u", conn_handle);
    }
}

const uint8_t *noise_get_local_peer_id(void)
{
    return s_peer_id;
}

const uint8_t *noise_get_static_public_key(void)
{
    return s_static_public;
}

void noise_begin_handshake(uint16_t conn_handle, const uint8_t peer_id[8], const char *nickname)
{
    (void)nickname;
    noise_session_t *session = find_session(conn_handle);
    if (session && session->handshake) {
        ESP_LOGI(TAG, "conn=%u handshake already active, ignoring new ANNOUNCE", conn_handle);
        return;
    }
    enqueue_event(NOISE_EVT_START, conn_handle, peer_id, true, NULL, 0);
}

bool noise_can_begin_handshake(uint16_t conn_handle)
{
    noise_session_t *session = find_session(conn_handle);
    return !(session && session->handshake);
}

bool noise_send_encrypted(uint16_t conn_handle, bitchat_noise_payload_type_t payload_type, const uint8_t *payload, size_t payload_len)
{
    noise_session_t *session = find_session(conn_handle);
    if (!session || !session->established) {
        return false;
    }
    uint8_t framed[NOISE_MAX_ENCRYPTED_PAYLOAD];
    size_t framed_len = sizeof(framed);
    if (payload_len + 1 > framed_len) {
        ESP_LOGW(TAG, "Payload too large for encryption");
        return false;
    }
    framed[0] = (uint8_t)payload_type;
    memcpy(framed + 1, payload, payload_len);
    uint8_t ciphertext[NOISE_MAX_ENCRYPTED_PAYLOAD];
    size_t ciphertext_len = sizeof(ciphertext);
    if (!encrypt_payload(session, framed, payload_len + 1, ciphertext, &ciphertext_len)) {
        ESP_LOGW(TAG, "Encryption failed for conn=%u", conn_handle);
    return false;
    }
    return encode_and_send(conn_handle, BITCHAT_MSG_NOISE_ENCRYPTED, session->peer_id, ciphertext, ciphertext_len, true) == ESP_OK;
}

bool noise_post_handshake_event(noise_evt_type_t type, uint16_t conn_handle, const uint8_t peer_id[8], bool initiator, const uint8_t *payload, uint16_t payload_len)
{
    return enqueue_event(type, conn_handle, peer_id, initiator, payload, payload_len);
}

esp_err_t noise_send_raw(uint16_t conn_handle, bitchat_message_type_t type, const uint8_t recipient[8], const uint8_t *payload, size_t payload_len)
{
    return encode_and_send(conn_handle, type, recipient, payload, payload_len, false);
}

void noise_poll(void)
{
    /* Session maintenance runs on the worker task's receive timeout; nothing
     * to do here. Kept for API compatibility with the main loop. */
}

esp_err_t bitchat_noise_init(void)
{
    memset(s_sessions, 0, sizeof(s_sessions));
    memset(s_identities, 0, sizeof(s_identities));
    s_worker_ready = false;
    load_identity();
    load_nickname();
    init_worker();
    return ESP_OK;
}

static void poll_session_maintenance(void)
{
    static uint64_t s_last_maintenance_ms;
    uint64_t uptime = esp_timer_get_time() / 1000ULL;
    if (uptime - s_last_maintenance_ms < 500) {
        return;
    }
    s_last_maintenance_ms = uptime;
    bool time_ok = bitchat_time_is_valid();
    uint32_t sync_gen = bitchat_time_sync_generation();

    for (size_t i = 0; i < NOISE_MAX_SESSIONS; ++i) {
        noise_session_t *session = &s_sessions[i];
        if (!session->in_use) {
            continue;
        }
        if (!bitchat_ble_conn_subscribed(session->conn_handle)) {
            continue; /* mute link; nothing we send can arrive */
        }
        if (s_identity_pending[i]) {
            try_send_identity(session);
        }
        /* Proactively establish a session with the direct peer. Upstream
         * treats a fresh 32-byte initiation as "the other side restarted":
         * it resets any stuck session and, on re-establishment, flushes the
         * peer's queued private messages toward us. */
        if (session->direct_peer && session->identity_sent &&
            !session->established && !session->handshake &&
            session->hs_attempts < 3 && uptime >= session->next_hs_ms) {
            session->hs_attempts++;
            session->next_hs_ms = uptime + 15000;
            ESP_LOGI(TAG, "conn=%u initiating session with direct peer (attempt %u)",
                     session->conn_handle, session->hs_attempts);
            noise_begin_handshake(session->conn_handle, session->peer_id, NULL);
        }
        if (session->identity_sent && session->sent_sync_gen != sync_gen) {
            /* Clock was corrected after our identity went out; the previous
             * announce carried a stale timestamp that iOS silently rejects.
             * Re-send with the freshly synced clock. */
            ESP_LOGI(TAG, "conn=%u clock re-synced; re-announcing identity", session->conn_handle);
            if (send_announce(session) && send_identity_announce(session)) {
                session->sent_sync_gen = sync_gen;
            }
            continue;
        }
        if (session->last_announce_ms == 0 || (uptime - session->last_announce_ms) >= ANNOUNCE_INTERVAL_MS) {
            if (time_ok && send_announce(session)) {
                session->last_announce_ms = uptime;
            }
        }
    }
}

