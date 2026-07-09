#include "bitle_courier.h"

#include <string.h>

#include "esp_log.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

#include "bitle_store.h"
#include "noise_handshake.h"

#define TAG_LEN            16
#define TAG_CONTEXT        "bitchat-courier-tag-v1"
#define MAX_LIFETIME_S     (25UL * 60UL * 60UL)   /* 24 h + 1 h slack */
#define REMOTE_COOLDOWN_S  600
#define MAX_COPIES         8

static const char *TAG = "bitle_courier";

/* Parsed CourierEnvelope TLVs (payload of a 0x04 packet). */
typedef struct {
    uint8_t recipient_tag[TAG_LEN];
    uint64_t expiry_ms;
    const uint8_t *ciphertext;
    uint16_t ciphertext_len;
    uint8_t copies;
    bool has_prekey_id;
    uint32_t prekey_id;
} envelope_t;

/* RAM side-state per stored envelope: spray dedup + remote-handover
 * cooldown. Lost on reboot, which only risks a redundant re-send that the
 * receiver dedups by ciphertext. */
typedef struct {
    bool in_use;
    uint8_t key[BITLE_STORE_KEY_LEN];
    uint32_t sprayed_mask;      /* bloom of peers already given a copy */
    uint32_t last_remote_s;
} side_state_t;

static side_state_t s_side[BITLE_COURIER_MAX_ENVELOPES];

/* Stored payload framing inside bitle_store: [depositor 8B][envelope TLVs].
 * The store's flags byte carries the remaining copy count. */
#define DEPOSITOR_LEN 8

static bool parse_envelope(const uint8_t *p, uint16_t len, envelope_t *env)
{
    memset(env, 0, sizeof(*env));
    env->copies = 1;
    bool have_tag = false, have_expiry = false, have_ct = false;
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
            if (l != TAG_LEN) {
                return false;
            }
            memcpy(env->recipient_tag, v, TAG_LEN);
            have_tag = true;
            break;
        case 0x02:
            if (l != 8) {
                return false;
            }
            env->expiry_ms = 0;
            for (int i = 0; i < 8; ++i) {
                env->expiry_ms = (env->expiry_ms << 8) | v[i];
            }
            have_expiry = true;
            break;
        case 0x03:
            if (l == 0) {
                return false;
            }
            env->ciphertext = v;
            env->ciphertext_len = l;
            have_ct = true;
            break;
        case 0x04:
            if (l != 1) {
                return false;
            }
            env->copies = v[0] < 1 ? 1 : (v[0] > MAX_COPIES ? MAX_COPIES : v[0]);
            break;
        case 0x05:
            if (l != 4) {
                return false;
            }
            env->prekey_id = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) |
                             ((uint32_t)v[2] << 8) | v[3];
            env->has_prekey_id = true;
            break;
        default:
            break; /* tolerant: skip unknown TLVs */
        }
    }
    return have_tag && have_expiry && have_ct;
}

/* Canonical re-encode (upstream field order; copies omitted when 1). */
static uint16_t encode_envelope(const envelope_t *env, uint8_t copies,
                                uint8_t *out, uint16_t out_max)
{
    uint16_t need = 3 + TAG_LEN + 3 + 8 + 3 + env->ciphertext_len +
                    (copies > 1 ? 4 : 0) + (env->has_prekey_id ? 7 : 0);
    if (need > out_max) {
        return 0;
    }
    uint16_t off = 0;
    out[off++] = 0x01; out[off++] = 0; out[off++] = TAG_LEN;
    memcpy(out + off, env->recipient_tag, TAG_LEN);
    off += TAG_LEN;
    out[off++] = 0x02; out[off++] = 0; out[off++] = 8;
    for (int i = 7; i >= 0; --i) {
        out[off++] = (env->expiry_ms >> (i * 8)) & 0xFF;
    }
    out[off++] = 0x03;
    out[off++] = (env->ciphertext_len >> 8) & 0xFF;
    out[off++] = env->ciphertext_len & 0xFF;
    memcpy(out + off, env->ciphertext, env->ciphertext_len);
    off += env->ciphertext_len;
    if (copies > 1) {
        out[off++] = 0x04; out[off++] = 0; out[off++] = 1;
        out[off++] = copies;
    }
    if (env->has_prekey_id) {
        out[off++] = 0x05; out[off++] = 0; out[off++] = 4;
        out[off++] = (env->prekey_id >> 24) & 0xFF;
        out[off++] = (env->prekey_id >> 16) & 0xFF;
        out[off++] = (env->prekey_id >> 8) & 0xFF;
        out[off++] = env->prekey_id & 0xFF;
    }
    return off;
}

/* tag = HMAC-SHA256(key = recipient noise static pubkey,
 *                   msg = "bitchat-courier-tag-v1" || epochDay u32 BE)[0..16) */
static void tag_for_day(const uint8_t noise_key[32], uint32_t epoch_day, uint8_t out[TAG_LEN])
{
    uint8_t msg[sizeof(TAG_CONTEXT) - 1 + 4];
    memcpy(msg, TAG_CONTEXT, sizeof(TAG_CONTEXT) - 1);
    msg[sizeof(TAG_CONTEXT) - 1] = (epoch_day >> 24) & 0xFF;
    msg[sizeof(TAG_CONTEXT)] = (epoch_day >> 16) & 0xFF;
    msg[sizeof(TAG_CONTEXT) + 1] = (epoch_day >> 8) & 0xFF;
    msg[sizeof(TAG_CONTEXT) + 2] = epoch_day & 0xFF;
    uint8_t mac[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    noise_key, 32, msg, sizeof(msg), mac);
    memcpy(out, mac, TAG_LEN);
}

/* Matchers test {day-1, day, day+1} (day-1 clamped at 0). */
static void candidate_tags(const uint8_t noise_key[32], uint64_t now_ms,
                           uint8_t out[3][TAG_LEN])
{
    uint32_t day = (uint32_t)((now_ms / 1000ULL) / 86400ULL);
    tag_for_day(noise_key, day == 0 ? 0 : day - 1, out[0]);
    tag_for_day(noise_key, day, out[1]);
    tag_for_day(noise_key, day + 1, out[2]);
}

static void envelope_key(const envelope_t *env, uint8_t out[BITLE_STORE_KEY_LEN])
{
    uint8_t digest[32];
    mbedtls_sha256(env->ciphertext, env->ciphertext_len, digest, 0);
    memcpy(out, digest, BITLE_STORE_KEY_LEN);
}

static side_state_t *side_get(const uint8_t key[BITLE_STORE_KEY_LEN], bool create)
{
    side_state_t *free_slot = NULL;
    for (size_t i = 0; i < BITLE_COURIER_MAX_ENVELOPES; ++i) {
        if (s_side[i].in_use && memcmp(s_side[i].key, key, BITLE_STORE_KEY_LEN) == 0) {
            return &s_side[i];
        }
        if (!s_side[i].in_use && !free_slot) {
            free_slot = &s_side[i];
        }
    }
    if (!create) {
        return NULL;
    }
    /* No free slot: reclaim one whose envelope no longer exists in the store
     * (side state is never explicitly freed on delete/eviction). */
    if (!free_slot) {
        for (size_t i = 0; i < BITLE_COURIER_MAX_ENVELOPES; ++i) {
            if (!bitle_store_contains(s_side[i].key)) {
                free_slot = &s_side[i];
                break;
            }
        }
    }
    if (!free_slot) {
        /* All slots track live envelopes; skip dedup rather than corrupt an
         * unrelated entry. Worst case is a redundant re-spray, which the
         * receiver dedups by ciphertext. */
        return NULL;
    }
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = true;
    memcpy(free_slot->key, key, BITLE_STORE_KEY_LEN);
    return free_slot;
}

static uint32_t peer_bit(const uint8_t peer_id[8])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 8; ++i) {
        h = (h ^ peer_id[i]) * 16777619u;
    }
    return 1u << (h & 31);
}

#define ANNOUNCE_MAX_DELIVER 8
#define ANNOUNCE_MAX_SPRAY   6

/* Deferred store rewrite: spraying reduces an envelope's copy count, which
 * means re-writing the record. That mutation MUST NOT happen inside the
 * bitle_store_iterate callback (the store lock is held and the index is
 * being walked), so ops are collected here and applied after iteration. */
typedef struct {
    uint8_t key[BITLE_STORE_KEY_LEN];
    uint32_t expiry_s;
    uint8_t copies;
    uint16_t len;
    uint8_t payload[BITLE_STORE_PAYLOAD_MAX];
} spray_op_t;

typedef struct {
    uint16_t conn_handle;
    const uint8_t *peer_id;
    const uint8_t (*tags)[TAG_LEN];
    bool is_direct;
    bool verified;
    uint64_t now_ms;
    uint8_t deliver_keys[ANNOUNCE_MAX_DELIVER][BITLE_STORE_KEY_LEN];
    size_t deliver_count;
    spray_op_t spray_ops[ANNOUNCE_MAX_SPRAY];
    size_t spray_count;
    uint16_t sent;
} announce_ctx_t;

static bool tag_matches(const envelope_t *env, const uint8_t (*tags)[TAG_LEN])
{
    for (int i = 0; i < 3; ++i) {
        if (memcmp(env->recipient_tag, tags[i], TAG_LEN) == 0) {
            return true;
        }
    }
    return false;
}

static bool send_envelope(uint16_t conn_handle, const uint8_t recipient[8],
                          const envelope_t *env, uint8_t copies)
{
    uint8_t payload[BITLE_STORE_PAYLOAD_MAX];
    uint16_t len = encode_envelope(env, copies, payload, sizeof(payload));
    if (!len) {
        return false;
    }
    return noise_send_packet(conn_handle, BITCHAT_MSG_COURIER_ENVELOPE,
                             recipient, payload, len, 7, true) == ESP_OK;
}

static bool announce_iter(const uint8_t key[BITLE_STORE_KEY_LEN], uint32_t expiry_s,
                          uint8_t flags, const uint8_t *payload, uint16_t payload_len,
                          void *arg)
{
    (void)expiry_s;
    announce_ctx_t *ctx = (announce_ctx_t *)arg;
    if (payload_len <= DEPOSITOR_LEN) {
        return true;
    }
    envelope_t env;
    if (!parse_envelope(payload + DEPOSITOR_LEN, payload_len - DEPOSITOR_LEN, &env)) {
        return true;
    }
    uint8_t copies = flags ? flags : 1;

    if (tag_matches(&env, ctx->tags)) {
        if (ctx->is_direct) {
            /* Owner is on a direct link: hand the mail over, then drop it. */
            if (ctx->deliver_count < ANNOUNCE_MAX_DELIVER &&
                send_envelope(ctx->conn_handle, ctx->peer_id, &env, 1)) {
                memcpy(ctx->deliver_keys[ctx->deliver_count++], key, BITLE_STORE_KEY_LEN);
                ctx->sent++;
            }
        } else {
            /* Owner heard through the mesh: flood one copy toward them,
             * keep ours, back off per envelope. */
            side_state_t *side = side_get(key, true);
            uint32_t now_s = (uint32_t)(ctx->now_ms / 1000ULL);
            if (side && now_s - side->last_remote_s >= REMOTE_COOLDOWN_S) {
                side->last_remote_s = now_s;
                if (send_envelope(ctx->conn_handle, ctx->peer_id, &env, 1)) {
                    ctx->sent++;
                }
            }
        }
        return true;
    }

    /* Not theirs: spray extra copies to other verified direct carriers so
     * mail diffuses across the mesh desert. The copy-count rewrite is
     * deferred (see spray_op_t) — never mutate the store mid-iterate. */
    if (ctx->is_direct && ctx->verified && copies > 1 &&
        ctx->spray_count < ANNOUNCE_MAX_SPRAY &&
        memcmp(payload, ctx->peer_id, DEPOSITOR_LEN) != 0) {
        side_state_t *side = side_get(key, true);
        uint32_t bit = peer_bit(ctx->peer_id);
        if (side && !(side->sprayed_mask & bit)) {
            uint8_t give = copies / 2;
            if (send_envelope(ctx->conn_handle, ctx->peer_id, &env, give)) {
                side->sprayed_mask |= bit;
                ctx->sent++;
                spray_op_t *op = &ctx->spray_ops[ctx->spray_count];
                memcpy(op->key, key, BITLE_STORE_KEY_LEN);
                op->expiry_s = expiry_s;
                op->copies = copies - give;
                memcpy(op->payload, payload, DEPOSITOR_LEN);
                uint16_t len = encode_envelope(&env, op->copies,
                                               op->payload + DEPOSITOR_LEN,
                                               sizeof(op->payload) - DEPOSITOR_LEN);
                if (len) {
                    op->len = DEPOSITOR_LEN + len;
                    ctx->spray_count++;
                }
            }
        }
    }
    return true;
}

void bitle_courier_peer_announced(uint16_t conn_handle, const uint8_t peer_id[8],
                                  const uint8_t noise_key[32], bool verified,
                                  bool is_direct, uint64_t now_ms)
{
    if (!verified || bitle_store_count() == 0) {
        return;
    }
    uint8_t tags[3][TAG_LEN];
    candidate_tags(noise_key, now_ms, tags);

    announce_ctx_t ctx = {
        .conn_handle = conn_handle,
        .peer_id = peer_id,
        .tags = (const uint8_t (*)[TAG_LEN])tags,
        .is_direct = is_direct,
        .verified = verified,
        .now_ms = now_ms,
    };
    bitle_store_iterate(announce_iter, &ctx);
    /* Apply deferred store mutations now that iteration has released the
     * store lock and is no longer walking the index. */
    for (size_t i = 0; i < ctx.deliver_count; ++i) {
        bitle_store_delete(ctx.deliver_keys[i]);
    }
    for (size_t i = 0; i < ctx.spray_count; ++i) {
        spray_op_t *op = &ctx.spray_ops[i];
        bitle_store_put(op->key, op->expiry_s, op->copies, op->payload, op->len);
    }
    if (ctx.sent) {
        ESP_LOGI(TAG, "Handed %u envelope(s) toward peer (%s)", ctx.sent,
                 ctx.is_direct ? "direct" : "via mesh");
    }
}

typedef struct {
    const uint8_t *depositor;
    size_t count;
} depositor_count_ctx_t;

static bool depositor_count_iter(const uint8_t key[BITLE_STORE_KEY_LEN], uint32_t expiry_s,
                                 uint8_t flags, const uint8_t *payload, uint16_t payload_len,
                                 void *arg)
{
    (void)key;
    (void)expiry_s;
    (void)flags;
    depositor_count_ctx_t *ctx = (depositor_count_ctx_t *)arg;
    if (payload_len > DEPOSITOR_LEN && memcmp(payload, ctx->depositor, DEPOSITOR_LEN) == 0) {
        ctx->count++;
    }
    return true;
}

bool bitle_courier_accept(uint16_t conn_handle, const uint8_t depositor[8],
                          bool depositor_verified, const uint8_t *payload,
                          uint16_t payload_len, uint64_t now_ms)
{
    (void)conn_handle;
    if (!depositor_verified) {
        ESP_LOGW(TAG, "Rejected deposit from unverified peer");
        return false;
    }
    envelope_t env;
    if (!parse_envelope(payload, payload_len, &env)) {
        ESP_LOGW(TAG, "Malformed envelope rejected");
        return false;
    }
    if (now_ms >= env.expiry_ms) {
        return false; /* expired (inclusive, mirrors upstream) */
    }
    if (env.expiry_ms > now_ms + (uint64_t)MAX_LIFETIME_S * 1000ULL) {
        ESP_LOGW(TAG, "Envelope lifetime beyond cap; rejected");
        return false;
    }
    if ((uint32_t)payload_len + DEPOSITOR_LEN > BITLE_STORE_PAYLOAD_MAX) {
        ESP_LOGW(TAG, "Envelope too large for mailbox (%u); rejected", payload_len);
        return false;
    }
    if (bitle_store_count() >= BITLE_COURIER_MAX_ENVELOPES) {
        ESP_LOGW(TAG, "Mailbox full (%u); rejected", (unsigned)bitle_store_count());
        return false;
    }

    uint8_t key[BITLE_STORE_KEY_LEN];
    envelope_key(&env, key);
    if (bitle_store_contains(key)) {
        return true; /* idempotent re-deposit */
    }

    depositor_count_ctx_t dctx = {.depositor = depositor};
    bitle_store_iterate(depositor_count_iter, &dctx);
    if (dctx.count >= BITLE_COURIER_MAX_PER_DEPOSITOR) {
        ESP_LOGW(TAG, "Depositor quota reached; rejected");
        return false;
    }

    uint8_t stored[BITLE_STORE_PAYLOAD_MAX];
    memcpy(stored, depositor, DEPOSITOR_LEN);
    memcpy(stored + DEPOSITOR_LEN, payload, payload_len);
    uint32_t expiry_s = (uint32_t)(env.expiry_ms / 1000ULL);
    if (bitle_store_put(key, expiry_s, env.copies, stored,
                        DEPOSITOR_LEN + payload_len) != ESP_OK) {
        return false;
    }
    ESP_LOGI(TAG, "Envelope deposited (%u B ciphertext, %u cop%s, mailbox %u/%u)",
             env.ciphertext_len, env.copies, env.copies == 1 ? "y" : "ies",
             (unsigned)bitle_store_count(), BITLE_COURIER_MAX_ENVELOPES);
    return true;
}

size_t bitle_courier_count(void)
{
    return bitle_store_count();
}

esp_err_t bitle_courier_init(void)
{
    memset(s_side, 0, sizeof(s_side));
    return bitle_store_init();
}
