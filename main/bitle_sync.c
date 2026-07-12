#include "bitle_sync.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "bitle_hash.h"

#include "bitchat_ble.h"
#include "bitchat_time.h"

static const char *TAG = "bitle_sync";

/* Upstream constants (GossipSyncManager / TransportConfig). */
#define GCS_P                7
#define GCS_MAX_BYTES        400
#define GCS_MAX_ACCEPT       1024
#define GCS_MAX_ELEMENTS     355        /* 400*8 / (P+2) */
#define WINDOW_ANNOUNCE_MS   (900ULL * 1000ULL)
#define WINDOW_MESSAGE_MS    (6ULL * 3600ULL * 1000ULL)
#define WINDOW_PREKEY_MS     (24ULL * 3600ULL * 1000ULL)
#define RATE_WINDOW_MS       30000ULL
#define RATE_MAX_RESPONSES   8
#define REQUEST_INTERVAL_MS  60000ULL
#define MAX_REPLAY_PER_REQ   40

/* SyncTypeFlags bit indices (little-endian byte order on the wire). */
#define FLAG_ANNOUNCE  (1ULL << 0)
#define FLAG_MESSAGE   (1ULL << 1)
#define FLAG_PREKEY    (1ULL << 9)
#define FLAG_GROUP     (1ULL << 10)

typedef struct {
    bool in_use;
    uint8_t type;
    uint8_t id[16];          /* SHA-256(type|sender|ts_BE|payload)[0..16) */
    uint64_t timestamp_ms;
    uint32_t ingest_seq;     /* local receive order; eviction basis */
    uint8_t owner[8];        /* announce: sender; prekey: bundle owner */
    uint16_t frame_len;
    uint8_t frame[BITLE_SYNC_FRAME_MAX];
} sync_slot_t;

static sync_slot_t s_slots[BITLE_SYNC_SLOTS];
static uint32_t s_ingest_seq;
static SemaphoreHandle_t s_lock;

typedef struct {
    uint16_t conn_handle;
    uint8_t count;
    uint64_t window_start_ms;
    uint64_t last_request_ms;
} peer_state_t;

static peer_state_t s_peers[8];

static peer_state_t *peer_state(uint16_t conn_handle)
{
    for (size_t i = 0; i < sizeof(s_peers) / sizeof(s_peers[0]); ++i) {
        if (s_peers[i].conn_handle == conn_handle) {
            return &s_peers[i];
        }
    }
    peer_state_t *victim = &s_peers[0];
    for (size_t i = 0; i < sizeof(s_peers) / sizeof(s_peers[0]); ++i) {
        if (s_peers[i].conn_handle == 0) {
            victim = &s_peers[i];
            break;
        }
        if (s_peers[i].last_request_ms < victim->last_request_ms) {
            victim = &s_peers[i];
        }
    }
    memset(victim, 0, sizeof(*victim));
    victim->conn_handle = conn_handle;
    return victim;
}

/* --- Packet identity + GCS bucket (double SHA-256, upstream-exact) ------- */

static void packet_id(const bitchat_packet_t *packet, uint8_t out[16])
{
    bitle_sha256_ctx_t ctx;
    bitle_sha256_begin(&ctx);
    uint8_t type = packet->type;
    bitle_sha256_update(&ctx, &type, 1);
    bitle_sha256_update(&ctx, packet->sender_id, 8);
    uint8_t ts[8];
    for (int i = 0; i < 8; ++i) {
        ts[i] = (packet->timestamp_ms >> ((7 - i) * 8)) & 0xFF;
    }
    bitle_sha256_update(&ctx, ts, 8);
    if (packet->payload_len) {
        bitle_sha256_update(&ctx, packet->payload, packet->payload_len);
    }
    uint8_t digest[32];
    bitle_sha256_finish(&ctx, digest);
    memcpy(out, digest, 16);
}

static uint64_t gcs_bucket(const uint8_t id[16], uint32_t m)
{
    if (m <= 1) {
        return 0;
    }
    uint8_t digest[32];
    bitle_sha256(id, 16, digest);
    uint64_t h = 0;
    for (int i = 0; i < 8; ++i) {
        h = (h << 8) | digest[i];
    }
    h &= 0x7fffffffffffffffULL;
    uint64_t v = h % (uint64_t)m;
    return v == 0 ? 1 : v;
}

/* --- MSB-first bit IO ----------------------------------------------------- */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t bit;
} bitwriter_t;

static bool bw_put(bitwriter_t *w, uint32_t bit)
{
    size_t byte = w->bit >> 3;
    if (byte >= w->cap) {
        return false;
    }
    if (bit) {
        w->buf[byte] |= 0x80 >> (w->bit & 7);
    }
    w->bit++;
    return true;
}

static bool bw_put_bits(bitwriter_t *w, uint64_t value, int count)
{
    for (int i = count - 1; i >= 0; --i) {
        if (!bw_put(w, (value >> i) & 1)) {
            return false;
        }
    }
    return true;
}

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t bit;
} bitreader_t;

static int br_get(bitreader_t *r)
{
    size_t byte = r->bit >> 3;
    if (byte >= r->len) {
        return -1;
    }
    int bit = (r->buf[byte] >> (7 - (r->bit & 7))) & 1;
    r->bit++;
    return bit;
}

/* Golomb-Rice encode of strictly-increasing buckets: delta-1 split into
 * unary quotient (q ones + terminating zero) and P-bit remainder. */
static size_t gcs_encode(const uint64_t *sorted, size_t count, int p,
                         uint8_t *out, size_t out_cap)
{
    memset(out, 0, out_cap);
    bitwriter_t w = {.buf = out, .cap = out_cap};
    uint64_t prev = 0;
    for (size_t i = 0; i < count; ++i) {
        uint64_t x = sorted[i] - prev;
        prev = sorted[i];
        uint64_t q = (x - 1) >> p;
        uint64_t r = (x - 1) & ((1ULL << p) - 1);
        while (q--) {
            if (!bw_put(&w, 1)) {
                return 0;
            }
        }
        if (!bw_put(&w, 0) || !bw_put_bits(&w, r, p)) {
            return 0;
        }
    }
    return (w.bit + 7) >> 3;
}

static size_t gcs_decode(const uint8_t *data, size_t len, int p, uint32_t m,
                         uint64_t *out, size_t out_cap)
{
    if (p < 1 || p > 32 || m <= 1) {
        return 0;
    }
    bitreader_t r = {.buf = data, .len = len};
    uint64_t acc = 0;
    size_t n = 0;
    while (n < out_cap) {
        uint64_t q = 0;
        int bit;
        while ((bit = br_get(&r)) == 1) {
            q++;
        }
        if (bit < 0) {
            break;
        }
        uint64_t rem = 0;
        bool ok = true;
        for (int i = 0; i < p; ++i) {
            int b = br_get(&r);
            if (b < 0) {
                ok = false;
                break;
            }
            rem = (rem << 1) | (uint64_t)b;
        }
        if (!ok) {
            break;
        }
        acc += (q << p) + rem + 1;
        if (acc >= m) {
            break;
        }
        out[n++] = acc;
    }
    return n;
}

static bool sorted_contains(const uint64_t *values, size_t count, uint64_t needle)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (values[mid] < needle) {
            lo = mid + 1;
        } else if (values[mid] > needle) {
            hi = mid;
        } else {
            return true;
        }
    }
    return false;
}

/* --- Store ----------------------------------------------------------------*/

static uint64_t type_window_ms(uint8_t type)
{
    switch (type) {
    case BITCHAT_MSG_ANNOUNCE: return WINDOW_ANNOUNCE_MS;
    case BITCHAT_MSG_PREKEY_BUNDLE: return WINDOW_PREKEY_MS;
    default: return WINDOW_MESSAGE_MS;
    }
}

static bool slot_fresh(const sync_slot_t *slot, uint64_t now_ms)
{
    uint64_t window = type_window_ms(slot->type);
    return now_ms < window || slot->timestamp_ms >= now_ms - window;
}

static size_t type_count(uint8_t announce, uint8_t prekey)
{
    size_t n = 0;
    for (size_t i = 0; i < BITLE_SYNC_SLOTS; ++i) {
        if (!s_slots[i].in_use) {
            continue;
        }
        bool is_announce = s_slots[i].type == BITCHAT_MSG_ANNOUNCE;
        bool is_prekey = s_slots[i].type == BITCHAT_MSG_PREKEY_BUNDLE;
        if ((announce && is_announce) || (prekey && is_prekey) ||
            (!announce && !prekey && !is_announce && !is_prekey)) {
            n++;
        }
    }
    return n;
}

static sync_slot_t *evict_for(uint8_t type, uint64_t now_ms)
{
    /* Expired first, then oldest of the same class. */
    sync_slot_t *victim = NULL;
    for (size_t i = 0; i < BITLE_SYNC_SLOTS; ++i) {
        sync_slot_t *s = &s_slots[i];
        if (!s->in_use) {
            return s;
        }
        if (!slot_fresh(s, now_ms)) {
            return s;
        }
    }
    for (size_t i = 0; i < BITLE_SYNC_SLOTS; ++i) {
        sync_slot_t *s = &s_slots[i];
        bool same_class = (s->type == type) ||
                          (type != BITCHAT_MSG_ANNOUNCE && type != BITCHAT_MSG_PREKEY_BUNDLE &&
                           s->type != BITCHAT_MSG_ANNOUNCE && s->type != BITCHAT_MSG_PREKEY_BUNDLE);
        if (!same_class) {
            continue;
        }
        /* Evict by local receive order, NOT packet timestamp: the timestamp
         * is attacker-controlled, so ordering eviction by it would let a
         * sybil stamp its floods "newest" and always evict legitimate data.
         * Receive order cannot be gamed. */
        if (!victim || s->ingest_seq < victim->ingest_seq) {
            victim = s;
        }
    }
    return victim;
}

/* Owner key for replace-semantics: announces keyed by sender, prekey
 * bundles keyed by the bundle's inner noise key (TLV 0x01) -> 8-byte ID. */
static bool derive_owner(const bitchat_packet_t *packet, uint8_t owner[8])
{
    if (packet->type == BITCHAT_MSG_ANNOUNCE) {
        memcpy(owner, packet->sender_id, 8);
        return true;
    }
    if (packet->type == BITCHAT_MSG_PREKEY_BUNDLE) {
        const uint8_t *p = packet->payload;
        uint16_t len = packet->payload_len;
        uint16_t off = 0;
        while (off + 3 <= len) {
            uint8_t t = p[off];
            uint16_t l = ((uint16_t)p[off + 1] << 8) | p[off + 2];
            off += 3;
            if (off + l > len) {
                return false;
            }
            if (t == 0x01 && l == 32) {
                uint8_t digest[32];
                bitle_sha256(p + off, 32, digest);
                memcpy(owner, digest, 8);
                return true;
            }
            off += l;
        }
        return false;
    }
    memset(owner, 0, 8);
    return true;
}

void bitle_sync_ingest(const bitchat_packet_t *packet, const uint8_t *raw, uint16_t raw_len)
{
    if (!raw || raw_len == 0 || raw_len > BITLE_SYNC_FRAME_MAX || !packet->payload) {
        return;
    }
    uint8_t type = packet->type;
    if (type != BITCHAT_MSG_ANNOUNCE && type != BITCHAT_MSG_MESSAGE &&
        type != BITCHAT_MSG_GROUP_MESSAGE && type != BITCHAT_MSG_PREKEY_BUNDLE) {
        return;
    }
    /* Only signed packets are worth carrying: receivers verify signatures
     * and would drop unsigned replays anyway. */
    if (!packet->has_signature) {
        return;
    }
    uint64_t now_ms = bitchat_time_now_ms();
    uint64_t window = type_window_ms(type);
    if (now_ms > window && packet->timestamp_ms < now_ms - window) {
        return; /* stale on arrival */
    }
    if (packet->timestamp_ms > now_ms + WINDOW_ANNOUNCE_MS) {
        return; /* implausibly far in the future */
    }

    uint8_t owner[8];
    if (!derive_owner(packet, owner)) {
        return;
    }
    uint8_t id[16];
    packet_id(packet, id);

    xSemaphoreTake(s_lock, portMAX_DELAY);

    sync_slot_t *target = NULL;
    for (size_t i = 0; i < BITLE_SYNC_SLOTS; ++i) {
        sync_slot_t *s = &s_slots[i];
        if (!s->in_use) {
            continue;
        }
        if (memcmp(s->id, id, 16) == 0) {
            xSemaphoreGive(s_lock);
            return; /* already stored */
        }
        /* Replace semantics for announce/prekey: newest per owner wins. */
        if ((type == BITCHAT_MSG_ANNOUNCE || type == BITCHAT_MSG_PREKEY_BUNDLE) &&
            s->type == type && memcmp(s->owner, owner, 8) == 0) {
            if (packet->timestamp_ms <= s->timestamp_ms) {
                xSemaphoreGive(s_lock);
                return;
            }
            target = s;
        }
    }

    if (!target) {
        size_t quota;
        size_t used;
        if (type == BITCHAT_MSG_ANNOUNCE) {
            quota = BITLE_SYNC_QUOTA_ANNOUNCE;
            used = type_count(1, 0);
        } else if (type == BITCHAT_MSG_PREKEY_BUNDLE) {
            quota = BITLE_SYNC_QUOTA_PREKEY;
            used = type_count(0, 1);
        } else {
            quota = BITLE_SYNC_QUOTA_MESSAGE;
            used = type_count(0, 0);
        }
        if (used >= quota) {
            target = evict_for(type, now_ms);
        } else {
            for (size_t i = 0; i < BITLE_SYNC_SLOTS; ++i) {
                if (!s_slots[i].in_use) {
                    target = &s_slots[i];
                    break;
                }
            }
            if (!target) {
                target = evict_for(type, now_ms);
            }
        }
    }
    if (!target) {
        xSemaphoreGive(s_lock);
        return;
    }

    target->in_use = true;
    target->type = type;
    memcpy(target->id, id, 16);
    target->timestamp_ms = packet->timestamp_ms;
    target->ingest_seq = ++s_ingest_seq;
    memcpy(target->owner, owner, 8);
    target->frame_len = raw_len;
    memcpy(target->frame, raw, raw_len);

    xSemaphoreGive(s_lock);
}

/* --- Serving requests ------------------------------------------------------*/

typedef struct {
    int p;
    uint32_t m;
    const uint8_t *filter;
    uint16_t filter_len;
    uint64_t type_flags;
    bool have_types;
    bool has_since;
    uint64_t since_ms;
} sync_request_t;

static bool parse_request(const uint8_t *p, uint16_t len, sync_request_t *req)
{
    memset(req, 0, sizeof(*req));
    req->p = -1;
    bool have_m = false, have_data = false;
    uint16_t off = 0;
    while (off + 3 <= len) {
        uint8_t t = p[off];
        uint16_t l = ((uint16_t)p[off + 1] << 8) | p[off + 2];
        off += 3;
        if (off + l > len) {
            return false;
        }
        const uint8_t *v = p + off;
        off += l;
        switch (t) {
        case 0x01:
            if (l == 1) {
                req->p = v[0];
            }
            break;
        case 0x02:
            if (l == 4) {
                req->m = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) |
                         ((uint32_t)v[2] << 8) | v[3];
                have_m = true;
            }
            break;
        case 0x03:
            if (l > GCS_MAX_ACCEPT) {
                return false;
            }
            req->filter = v;
            req->filter_len = l;
            have_data = true;
            break;
        case 0x04: {
            uint64_t flags = 0;
            for (uint16_t i = 0; i < l && i < 8; ++i) {
                flags |= (uint64_t)v[i] << (i * 8); /* little-endian! */
            }
            req->type_flags = flags;
            req->have_types = true;
            break;
        }
        case 0x05:
            if (l == 8) {
                req->since_ms = 0;
                for (int i = 0; i < 8; ++i) {
                    req->since_ms = (req->since_ms << 8) | v[i];
                }
                req->has_since = true;
            }
            break;
        default:
            break;
        }
    }
    if (req->p < 1 || req->p > 32 || !have_m || req->m == 0 || !have_data) {
        return false;
    }
    /* Default only when the flags TLV is ABSENT. A present-but-zero field
     * means "serve nothing" (matches upstream, where a non-nil empty
     * SyncTypeFlags resolves to the empty set, not the default). */
    if (!req->have_types) {
        req->type_flags = FLAG_ANNOUNCE | FLAG_MESSAGE;
    }
    return true;
}

static bool type_requested(uint8_t type, uint64_t flags)
{
    switch (type) {
    case BITCHAT_MSG_ANNOUNCE: return (flags & FLAG_ANNOUNCE) != 0;
    case BITCHAT_MSG_MESSAGE: return (flags & FLAG_MESSAGE) != 0;
    case BITCHAT_MSG_GROUP_MESSAGE: return (flags & FLAG_GROUP) != 0;
    case BITCHAT_MSG_PREKEY_BUNDLE: return (flags & FLAG_PREKEY) != 0;
    default: return false;
    }
}

void bitle_sync_handle_request(uint16_t conn_handle, const bitchat_packet_t *packet)
{
    if (packet->ttl != 0) {
        return; /* upstream requirement: requestSync is link-local, ttl 0 */
    }
    uint8_t sign_key[32];
    bool verified = false;
    if (!noise_get_peer_identity(conn_handle, NULL, sign_key, &verified) || !verified) {
        return;
    }

    /* Rate-limit BEFORE the expensive Ed25519 verify so a peer that has
     * completed one handshake cannot force an unbounded verify-per-frame CPU
     * load on the shared worker task by streaming requestSync frames. */
    uint64_t now_ms = bitchat_time_now_ms();
    peer_state_t *peer = peer_state(conn_handle);
    if (now_ms - peer->window_start_ms > RATE_WINDOW_MS) {
        peer->window_start_ms = now_ms;
        peer->count = 0;
    }
    if (peer->count >= RATE_MAX_RESPONSES) {
        return;
    }
    peer->count++;

    if (!noise_verify_packet_signature(packet, sign_key)) {
        ESP_LOGW(TAG, "conn=%u requestSync signature invalid", conn_handle);
        return;
    }

    sync_request_t req;
    if (!parse_request(packet->payload, packet->payload_len, &req)) {
        return;
    }

    static uint64_t buckets[GCS_MAX_ELEMENTS + 8];
    size_t bucket_count = gcs_decode(req.filter, req.filter_len, req.p, req.m,
                                     buckets, sizeof(buckets) / sizeof(buckets[0]));

    /* Select matching slots under the lock, then send OUTSIDE it: holding the
     * store mutex across BLE sends and pacing delays would block host-task
     * ingest and stall BLE processing for the whole replay. */
    uint16_t to_send[MAX_REPLAY_PER_REQ];
    size_t n_send = 0;
    size_t skipped = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < BITLE_SYNC_SLOTS; ++i) {
        sync_slot_t *s = &s_slots[i];
        if (!s->in_use || !type_requested(s->type, req.type_flags) ||
            !slot_fresh(s, now_ms)) {
            continue;
        }
        /* Announces and prekey bundles are exempt from the since-cursor. */
        if (req.has_since && s->type != BITCHAT_MSG_ANNOUNCE &&
            s->type != BITCHAT_MSG_PREKEY_BUNDLE && s->timestamp_ms < req.since_ms) {
            continue;
        }
        if (req.m > 1 && bucket_count &&
            sorted_contains(buckets, bucket_count, gcs_bucket(s->id, req.m))) {
            continue; /* peer already has it */
        }
        if (n_send >= MAX_REPLAY_PER_REQ) {
            skipped++;
            continue;
        }
        to_send[n_send++] = (uint16_t)i;
    }
    xSemaphoreGive(s_lock);

    size_t sent = 0;
    for (size_t k = 0; k < n_send; ++k) {
        /* Re-copy under a brief lock in case the slot was reused since select. */
        uint8_t frame[BITLE_SYNC_FRAME_MAX];
        uint16_t len = 0;
        xSemaphoreTake(s_lock, portMAX_DELAY);
        sync_slot_t *s = &s_slots[to_send[k]];
        if (s->in_use) {
            len = s->frame_len;
            memcpy(frame, s->frame, len);
        }
        xSemaphoreGive(s_lock);
        if (!len) {
            continue;
        }
        /* Replay verbatim with ttl=0 and the RSR flag: both live in the header
         * outside the signature, so patch the copy in place. */
        frame[2] = 0;           /* ttl */
        frame[11] |= 0x10;      /* flags: isRSR */
        if (bitchat_ble_send(conn_handle, frame, len) == ESP_OK) {
            sent++;
        }
        if ((sent & 0x03) == 0) {
            vTaskDelay(pdMS_TO_TICKS(20)); /* let NimBLE drain its mbuf pool */
        }
    }

    if (sent || skipped) {
        ESP_LOGI(TAG, "conn=%u sync replayed %u packet(s)%s", conn_handle,
                 (unsigned)sent, skipped ? " (budget hit, more remain)" : "");
    }
}

/* --- Our own requests (pull from passing phones) --------------------------*/

static size_t collect_buckets(uint64_t flags, uint32_t *out_m, uint64_t *buckets, size_t cap)
{
    uint64_t now_ms = bitchat_time_now_ms();
    uint8_t ids[BITLE_SYNC_SLOTS][16];
    size_t n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < BITLE_SYNC_SLOTS && n < cap; ++i) {
        sync_slot_t *s = &s_slots[i];
        if (s->in_use && type_requested(s->type, flags) && slot_fresh(s, now_ms)) {
            memcpy(ids[n], s->id, 16);
            n++;
        }
    }
    xSemaphoreGive(s_lock);

    uint32_t m = n ? (uint32_t)(n << GCS_P) : 1;
    *out_m = m;
    size_t count = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t b = gcs_bucket(ids[i], m);
        /* insertion sort keeping strictly-increasing order (dups dropped) */
        size_t j = count;
        while (j > 0 && buckets[j - 1] > b) {
            j--;
        }
        if (j > 0 && buckets[j - 1] == b) {
            continue;
        }
        memmove(&buckets[j + 1], &buckets[j], (count - j) * sizeof(uint64_t));
        buckets[j] = b;
        count++;
    }
    return count;
}

static void send_request(uint16_t conn_handle, const uint8_t peer_id[8])
{
    uint64_t flags = FLAG_ANNOUNCE | FLAG_MESSAGE | FLAG_GROUP | FLAG_PREKEY;
    static uint64_t buckets[BITLE_SYNC_SLOTS];
    uint32_t m = 1;
    size_t count = collect_buckets(flags, &m, buckets, BITLE_SYNC_SLOTS);

    uint8_t filter[GCS_MAX_BYTES];
    size_t filter_len = count ? gcs_encode(buckets, count, GCS_P, filter, sizeof(filter)) : 0;

    uint8_t payload[3 + 1 + 3 + 4 + 3 + GCS_MAX_BYTES + 3 + 2];
    uint16_t off = 0;
    payload[off++] = 0x01; payload[off++] = 0; payload[off++] = 1;
    payload[off++] = GCS_P;
    payload[off++] = 0x02; payload[off++] = 0; payload[off++] = 4;
    payload[off++] = (m >> 24) & 0xFF;
    payload[off++] = (m >> 16) & 0xFF;
    payload[off++] = (m >> 8) & 0xFF;
    payload[off++] = m & 0xFF;
    payload[off++] = 0x03;
    payload[off++] = (filter_len >> 8) & 0xFF;
    payload[off++] = filter_len & 0xFF;
    memcpy(payload + off, filter, filter_len);
    off += filter_len;
    /* SyncTypeFlags: little-endian, trailing zeros trimmed -> 2 bytes for
     * announce|message plus prekey(bit9)|group(bit10). */
    payload[off++] = 0x04; payload[off++] = 0; payload[off++] = 2;
    payload[off++] = (uint8_t)(FLAG_ANNOUNCE | FLAG_MESSAGE);
    payload[off++] = (uint8_t)((FLAG_PREKEY | FLAG_GROUP) >> 8);

    if (noise_send_packet(conn_handle, BITCHAT_MSG_REQUEST_SYNC, peer_id,
                          payload, off, 0, true) == ESP_OK) {
        ESP_LOGD(TAG, "conn=%u requestSync sent (%u known)", conn_handle, (unsigned)count);
    }
}

void bitle_sync_tick(uint16_t conn_handle, const uint8_t peer_id[8], uint64_t uptime_ms)
{
    peer_state_t *peer = peer_state(conn_handle);
    if (peer->last_request_ms && uptime_ms - peer->last_request_ms < REQUEST_INTERVAL_MS) {
        return;
    }
    peer->last_request_ms = uptime_ms ? uptime_ms : 1;
    send_request(conn_handle, peer_id);
}

size_t bitle_sync_count(void)
{
    size_t n = 0;
    for (size_t i = 0; i < BITLE_SYNC_SLOTS; ++i) {
        if (s_slots[i].in_use) {
            n++;
        }
    }
    return n;
}

esp_err_t bitle_sync_init(void)
{
    memset(s_slots, 0, sizeof(s_slots));
    memset(s_peers, 0, sizeof(s_peers));
    s_lock = xSemaphoreCreateMutex();
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}
