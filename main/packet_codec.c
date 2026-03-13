#include "packet_codec.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include <string.h>

#include "bitchat_ble.h"

static const char *TAG = "packet_codec";

static uint8_t read_u8(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 1 > len) {
        *ok = false;
        return 0;
    }
    return data[(*offset)++];
}

static uint16_t read_u16_be(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 2 > len) {
        *ok = false;
        return 0;
    }
    uint16_t value = (data[*offset] << 8) | data[*offset + 1];
    *offset += 2;
    return value;
}

static uint64_t read_u64_be(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 8 > len) {
        *ok = false;
        return 0;
    }
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | data[*offset + i];
    }
    *offset += 8;
    return value;
}

void packet_codec_init(void)
{
}

bool bitchat_packet_decode(const uint8_t *data, size_t len, bitchat_packet_t *out_packet)
{
    if (!data || !out_packet || len == 0) {
        return false;
    }
    memset(out_packet, 0, sizeof(*out_packet));
    size_t offset = 0;
    bool ok = true;

    out_packet->version = read_u8(data, len, &offset, &ok);
    out_packet->type = read_u8(data, len, &offset, &ok);
    out_packet->ttl = read_u8(data, len, &offset, &ok);
    out_packet->timestamp_ms = read_u64_be(data, len, &offset, &ok);
    uint8_t flags = read_u8(data, len, &offset, &ok);
    uint16_t payload_len = read_u16_be(data, len, &offset, &ok);

    if (!ok || out_packet->version != 1) {
        ESP_LOGW(TAG, "Invalid packet header");
        return false;
    }

    if (offset + sizeof(out_packet->sender_id) > len) {
        ESP_LOGW(TAG, "Missing sender id bytes");
        return false;
    }
    memcpy(out_packet->sender_id, data + offset, sizeof(out_packet->sender_id));
    offset += 8;

    if (flags & 0x01) {
        out_packet->has_recipient = true;
        if (offset + sizeof(out_packet->recipient_id) > len) {
            ESP_LOGW(TAG, "Missing recipient id bytes");
            return false;
        }
        memcpy(out_packet->recipient_id, data + offset, sizeof(out_packet->recipient_id));
        offset += 8;
    }

    if (offset + payload_len > len) {
        ESP_LOGW(TAG, "Payload length exceeds buffer");
        return false;
    }

    if (payload_len > 0) {
        out_packet->payload = heap_caps_malloc(payload_len, MALLOC_CAP_8BIT);
        if (!out_packet->payload) {
            ESP_LOGE(TAG, "Failed to allocate payload");
            return false;
        }
        memcpy(out_packet->payload, data + offset, payload_len);
    }
    out_packet->payload_len = payload_len;
    offset += payload_len;

    if (flags & 0x02) {
        out_packet->has_signature = true;
        if (offset + 64 > len) {
            ESP_LOGW(TAG, "Missing signature bytes");
            bitchat_packet_free(out_packet);
            return false;
        }
        memcpy(out_packet->signature, data + offset, 64);
        offset += 64;
    }

    return true;
}

bool bitchat_packet_encode(const bitchat_packet_t *packet, uint8_t *out_buf, size_t *out_len, size_t max_len)
{
    if (!packet || !out_buf || !out_len) {
        return false;
    }
    size_t offset = 0;

    size_t header_len = 1 /*version*/ + 1 /*type*/ + 1 /*ttl*/ + 8 /*timestamp*/ + 1 /*flags*/ + 2 /*payload len*/ + 8 /*sender*/
                        + (packet->has_recipient ? 8 : 0);
    size_t total_len = header_len + packet->payload_len + (packet->has_signature ? 64 : 0);
    if (total_len > max_len) {
        return false;
    }

    out_buf[offset++] = packet->version;
    out_buf[offset++] = packet->type;
    out_buf[offset++] = packet->ttl;

    for (int i = 7; i >= 0; --i) {
        out_buf[offset++] = (packet->timestamp_ms >> (i * 8)) & 0xFF;
    }

    uint8_t flags = 0;
    if (packet->has_recipient) {
        flags |= 0x01;
    }
    if (packet->has_signature) {
        flags |= 0x02;
    }
    out_buf[offset++] = flags;

    out_buf[offset++] = (packet->payload_len >> 8) & 0xFF;
    out_buf[offset++] = packet->payload_len & 0xFF;

    memcpy(out_buf + offset, packet->sender_id, 8);
    offset += 8;

    if (packet->has_recipient) {
        memcpy(out_buf + offset, packet->recipient_id, 8);
        offset += 8;
    }

    if (packet->payload_len > 0) {
        if (!packet->payload) {
            return false;
        }
        memcpy(out_buf + offset, packet->payload, packet->payload_len);
        offset += packet->payload_len;
    }

    if (packet->has_signature) {
        memcpy(out_buf + offset, packet->signature, 64);
        offset += 64;
    }

    *out_len = offset;
    return true;
}

bool bitchat_packet_encode_canonical(const bitchat_packet_t *packet, uint8_t *out_buf, size_t *out_len, size_t max_len)
{
    bitchat_packet_t canonical = *packet;
    canonical.ttl = 0;
    canonical.has_signature = false;
    memset(canonical.signature, 0, sizeof(canonical.signature));
    size_t len = max_len;
    if (!bitchat_packet_encode(&canonical, out_buf, &len, max_len)) {
        return false;
    }
    *out_len = len;
    return true;
}

void bitchat_packet_free(bitchat_packet_t *packet)
{
    if (packet->payload) {
        heap_caps_free(packet->payload);
    }
    memset(packet, 0, sizeof(*packet));
}

bool packet_codec_self_test(void)
{
    const uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t recipient[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint8_t signature[64] = {
        0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1,
        0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1,
        0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
        0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1,
        0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9,
        0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1,
        0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
    };

    bitchat_packet_t packet = {0};
    packet.version = 1;
    packet.type = BITCHAT_MSG_NOISE_ENCRYPTED;
    packet.ttl = 7;
    packet.timestamp_ms = 0x0102030405060708ULL;
    memcpy(packet.sender_id, (uint8_t[]){0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27}, sizeof(packet.sender_id));
    memcpy(packet.recipient_id, recipient, sizeof(packet.recipient_id));
    packet.has_recipient = true;
    packet.payload = (uint8_t *)payload;
    packet.payload_len = sizeof(payload);
    memcpy(packet.signature, signature, sizeof(packet.signature));
    packet.has_signature = true;

    uint8_t encoded[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t encoded_len = sizeof(encoded);
    if (!bitchat_packet_encode(&packet, encoded, &encoded_len, sizeof(encoded))) {
        return false;
    }

    bitchat_packet_t decoded;
    if (!bitchat_packet_decode(encoded, encoded_len, &decoded)) {
        return false;
    }

    bool ok = decoded.version == packet.version &&
              decoded.type == packet.type &&
              decoded.ttl == packet.ttl &&
              decoded.timestamp_ms == packet.timestamp_ms &&
              decoded.has_recipient == packet.has_recipient &&
              decoded.payload_len == packet.payload_len &&
              decoded.has_signature == packet.has_signature &&
              memcmp(decoded.sender_id, packet.sender_id, sizeof(packet.sender_id)) == 0 &&
              memcmp(decoded.recipient_id, packet.recipient_id, sizeof(packet.recipient_id)) == 0 &&
              memcmp(decoded.payload, packet.payload, packet.payload_len) == 0 &&
              memcmp(decoded.signature, packet.signature, sizeof(packet.signature)) == 0;

    bitchat_packet_free(&decoded);
    return ok;
}

