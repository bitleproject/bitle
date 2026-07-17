#include "bitle_mesh.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "bitchat_ble.h"
#include "bitchat_time.h"
#include "bitle_link.h"
#include "bitle_ota.h"
#include "bitle_sync.h"
#include "noise_handshake.h"
#include "packet_codec.h"

static const char *TAG = "bitle_mesh";

static SemaphoreHandle_t s_lock;

static void dispatch_packet(uint16_t link_handle, const bitchat_packet_t *packet);
static uint64_t relay_fingerprint(const uint8_t *data, size_t len);
static bool relay_seen_before(uint64_t fingerprint);

/* --- Fragment reassembly ---------------------------------------------------
 * Phones fragment packets that exceed the link write budget (a 256-padded
 * packet does not fit ATT_MTU-3 = 253 at MTU 256), so directly connected
 * peers routinely fragment handshakes and DMs. Fragment payload layout:
 * [8B fragment ID][2B index BE][2B total BE][1B original type][chunk].
 * Reassembled bytes are the original packet's full encoding. */

#define FRAG_SLOTS      2
#define FRAG_MAX_PARTS  4
/* A fragment chunk can be as large as the negotiated MTU allows: at ATT MTU
 * 517 (what iOS uses) that is ~ATT_MTU-3 minus the 13-byte fragment header,
 * so a large DM fragments into ~500-byte chunks. A smaller cap here silently
 * drops those (chunk_len > cap => return, packet never reassembled). Size to
 * hold the largest possible chunk; FRAG_MAX_PARTS*FRAG_PART_MAX still exceeds
 * the 520-byte max packet. */
#define FRAG_PART_MAX   501
#define FRAG_TIMEOUT_MS 15000ULL

typedef struct {
    bool in_use;
    uint64_t frag_id;
    uint8_t sender[8];
    uint16_t total;
    uint32_t have_mask;
    uint64_t started_ms;
    uint16_t part_len[FRAG_MAX_PARTS];
    uint8_t part[FRAG_MAX_PARTS][FRAG_PART_MAX];
} frag_slot_t;

static frag_slot_t s_frag_slots[FRAG_SLOTS];

static void handle_fragment(uint16_t link_handle, const bitchat_packet_t *packet)
{
    const uint8_t *p = packet->payload;
    if (!p || packet->payload_len < 13) {
        return;
    }
    uint64_t frag_id = 0;
    for (int i = 0; i < 8; ++i) {
        frag_id = (frag_id << 8) | p[i];
    }
    uint16_t index = ((uint16_t)p[8] << 8) | p[9];
    uint16_t total = ((uint16_t)p[10] << 8) | p[11];
    uint16_t chunk_len = packet->payload_len - 13;
    if (total == 0 || index >= total || chunk_len == 0) {
        return;
    }
    if (total > FRAG_MAX_PARTS || chunk_len > FRAG_PART_MAX) {
        ESP_LOGI(TAG, "Fragment exceeds local limits (total=%u len=%u); relay-only", total, chunk_len);
        return;
    }

    uint64_t now = esp_timer_get_time() / 1000ULL;
    frag_slot_t *slot = NULL;
    frag_slot_t *free_slot = NULL;
    frag_slot_t *oldest = &s_frag_slots[0];
    for (size_t i = 0; i < FRAG_SLOTS; ++i) {
        frag_slot_t *s = &s_frag_slots[i];
        if (s->in_use && now - s->started_ms > FRAG_TIMEOUT_MS) {
            s->in_use = false;
        }
        if (s->in_use && s->frag_id == frag_id &&
            memcmp(s->sender, packet->sender_id, sizeof(s->sender)) == 0) {
            slot = s;
        } else if (!s->in_use && !free_slot) {
            free_slot = s;
        }
        if (s->started_ms < oldest->started_ms) {
            oldest = s;
        }
    }
    if (!slot) {
        slot = free_slot ? free_slot : oldest;
        memset(slot, 0, sizeof(*slot));
        slot->in_use = true;
        slot->frag_id = frag_id;
        memcpy(slot->sender, packet->sender_id, sizeof(slot->sender));
        slot->total = total;
        slot->started_ms = now;
    }
    if (slot->total != total) {
        return;
    }
    slot->part_len[index] = chunk_len;
    memcpy(slot->part[index], p + 13, chunk_len);
    slot->have_mask |= 1u << index;

    uint32_t want_mask = (1u << total) - 1;
    if ((slot->have_mask & want_mask) != want_mask) {
        return;
    }

    static uint8_t reassembled[FRAG_MAX_PARTS * FRAG_PART_MAX];
    size_t reassembled_len = 0;
    for (uint16_t i = 0; i < total; ++i) {
        memcpy(reassembled + reassembled_len, slot->part[i], slot->part_len[i]);
        reassembled_len += slot->part_len[i];
    }
    slot->in_use = false;

    bitchat_packet_t inner;
    if (!bitchat_packet_decode(reassembled, reassembled_len, &inner)) {
        ESP_LOGW(TAG, "Failed to decode reassembled packet (%u bytes)", (unsigned)reassembled_len);
        return;
    }
    /* Dedup the REASSEMBLED bytes too: an echoed copy of a fragmented
     * packet is re-fragmented differently by each relayer, so the raw
     * fragment frames differ, but the inner packet is byte-identical —
     * this is where a duplicate handshake sneaks back in. */
    if (relay_seen_before(relay_fingerprint(reassembled, reassembled_len))) {
        ESP_LOGD(TAG, "duplicate reassembled packet dropped (type=0x%02X)", inner.type);
        bitchat_packet_free(&inner);
        return;
    }
    ESP_LOGI(TAG, "Reassembled packet type=0x%02X len=%u from %u fragments",
             inner.type, inner.payload_len, total);
    if (inner.type != BITCHAT_MSG_FRAGMENT) {
        dispatch_packet(link_handle, &inner);
    }
    bitchat_packet_free(&inner);
}

static bool is_broadcast_recipient(const bitchat_packet_t *packet)
{
    if (!packet->has_recipient) {
        return true;
    }
    for (size_t i = 0; i < sizeof(packet->recipient_id); ++i) {
        if (packet->recipient_id[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

static bool is_local_recipient(const bitchat_packet_t *packet)
{
    return packet->has_recipient &&
           memcmp(packet->recipient_id, noise_get_local_peer_id(), sizeof(packet->recipient_id)) == 0;
}

static void dispatch_packet(uint16_t link_handle, const bitchat_packet_t *packet)
{
    ESP_LOGI(TAG, "RX conn=%u type=0x%02X len=%u ttl=%u from=%02X%02X%02X%02X to=%s%s",
             link_handle, packet->type, packet->payload_len, packet->ttl,
             packet->sender_id[0], packet->sender_id[1], packet->sender_id[2], packet->sender_id[3],
             is_broadcast_recipient(packet) ? "bcast" : (is_local_recipient(packet) ? "us" : "other"),
             packet->is_compressed ? " (compressed)" : "");

    /* Harvest wall time only from directly-connected peers (packets still at
     * their origin TTL). Announces flow through the authoritative path (which
     * knows the sender's infra/authority status); other direct packet types
     * feed only the tentative path, which bootstraps a fresh clock but never
     * makes a large post-sync correction — so a hostile relayed or replayed
     * timestamp cannot move an established clock. */
    if (packet->ttl == BITLE_ORIGIN_TTL && packet->type != BITCHAT_MSG_ANNOUNCE) {
        bitchat_time_consider_peer(packet->timestamp_ms);
    }

    if (packet->is_compressed) {
        /* No zlib inflate on this target; the relay path still forwards the
         * raw bytes, we just cannot act on the payload locally. */
        return;
    }
    if (!is_broadcast_recipient(packet) && !is_local_recipient(packet)) {
        return; /* directed at another peer; the relay layer forwards it */
    }

    switch (packet->type) {
    case BITCHAT_MSG_ANNOUNCE:
        noise_handle_announce(link_handle, packet);
        break;
    case BITCHAT_MSG_NOISE_HANDSHAKE:
        noise_handle_handshake(link_handle, packet);
        break;
    case BITCHAT_MSG_NOISE_ENCRYPTED:
        noise_handle_encrypted(link_handle, packet);
        break;
    case BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE:
        noise_handle_identity_announce(link_handle, packet);
        break;
    case BITCHAT_MSG_MESSAGE:
        noise_handle_public_message(link_handle, packet);
        break;
    case BITCHAT_MSG_FRAGMENT:
        handle_fragment(link_handle, packet);
        break;
    case BITLE_MSG_OTA_MANIFEST:
    case BITLE_MSG_OTA_REQ:
    case BITLE_MSG_OTA_CHUNK:
    case BITLE_MSG_OTA_STATUS:
        bitle_ota_handle_packet(link_handle, packet);
        break;
    case BITCHAT_MSG_COURIER_ENVELOPE:
        if (is_local_recipient(packet)) {
            noise_handle_courier(link_handle, packet);
        }
        break;
    case BITCHAT_MSG_REQUEST_SYNC:
        noise_handle_request_sync(link_handle, packet);
        break;
    case BITCHAT_MSG_LEAVE:
        break;
    default:
        ESP_LOGD(TAG, "Ignoring packet type 0x%02X locally", packet->type);
        break;
    }
}

/* --- Mesh relay -----------------------------------------------------------
 * Forwards packets between links: TTL-decremented, deduplicated raw
 * re-broadcast of everything not addressed to (or sent by) this node. */

#define RELAY_CACHE_SIZE 64

static uint64_t s_relay_seen[RELAY_CACHE_SIZE];
static size_t s_relay_seen_next;

static uint64_t relay_fingerprint(const uint8_t *data, size_t len)
{
    /* FNV-1a over the packet bytes, skipping the TTL byte (offset 2), which
     * changes at every hop and must not defeat deduplication. */
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) {
        if (i == 2) {
            continue;
        }
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool relay_seen_before(uint64_t fingerprint)
{
    for (size_t i = 0; i < RELAY_CACHE_SIZE; ++i) {
        if (s_relay_seen[i] == fingerprint) {
            return true;
        }
    }
    s_relay_seen[s_relay_seen_next] = fingerprint;
    s_relay_seen_next = (s_relay_seen_next + 1) % RELAY_CACHE_SIZE;
    return false;
}

static void relay_packet(uint16_t src_link, uint8_t *buffer, uint16_t len, const bitchat_packet_t *packet)
{
    if (packet->ttl <= 1) {
        return;
    }
    if (memcmp(packet->sender_id, noise_get_local_peer_id(), sizeof(packet->sender_id)) == 0) {
        return; /* our own packet echoed back */
    }
    if (packet->type == BITCHAT_MSG_REQUEST_SYNC) {
        return; /* link-local by protocol */
    }
    if (is_local_recipient(packet)) {
        return; /* addressed to us; nothing to forward */
    }
    if (!packet->has_recipient && packet->type == BITCHAT_MSG_NOISE_HANDSHAKE) {
        return; /* undirected handshakes are link-local */
    }

    buffer[2] = packet->ttl - 1;

    int forwarded = bitle_link_broadcast(src_link, buffer, len);
    if (forwarded > 0) {
        ESP_LOGI(TAG, "Relayed type=0x%02X ttl=%u to %d link(s)", packet->type, buffer[2], forwarded);
    }
}

esp_err_t bitle_mesh_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}

bool bitle_mesh_inbound(uint16_t link_handle, uint8_t *buffer, uint16_t len)
{
    bitchat_packet_t packet;
    if (!bitchat_packet_decode(buffer, len, &packet)) {
        ESP_LOGW(TAG, "Failed to decode inbound packet len=%u", len);
        return false;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    /* Process each unique packet exactly once, no matter how many paths
     * deliver it (trunk + a phone echoing the relayed copy back, etc.).
     * Duplicate LOCAL processing is not idle work: a duplicate handshake
     * arriving on a different link captures the noise session onto that
     * link, and every reply then exits the wrong interface. Retries are
     * never byte-identical (fresh timestamps/nonces), so they pass. */
    if (relay_seen_before(relay_fingerprint(buffer, len))) {
        xSemaphoreGive(s_lock);
        ESP_LOGD(TAG, "duplicate packet dropped (type=0x%02X)", packet.type);
        bitchat_packet_free(&packet);
        return true;
    }
    dispatch_packet(link_handle, &packet);
    /* Dead-drop: keep recent signed public packets so passing phones can
     * sync from us later (the module filters types and enforces budgets). */
    if (!packet.is_compressed) {
        bitle_sync_ingest(&packet, buffer, len);
    }
    relay_packet(link_handle, buffer, len, &packet);
    xSemaphoreGive(s_lock);
    bitchat_packet_free(&packet);
    return true;
}
