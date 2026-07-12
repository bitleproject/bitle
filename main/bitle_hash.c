#include "bitle_hash.h"

#include <string.h>

#include "esp_log.h"

static const char *TAG = "bitle_hash";

#define SHA256_BLOCK 64

void bitle_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    size_t olen = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, data, len, out, 32, &olen) != PSA_SUCCESS ||
        olen != 32) {
        memset(out, 0xFF, 32);
    }
}

void bitle_sha256_begin(bitle_sha256_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx)); /* PSA_HASH_OPERATION_INIT is all-zero */
    if (psa_hash_setup(&ctx->op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        psa_hash_abort(&ctx->op);
    }
}

void bitle_sha256_update(bitle_sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return;
    }
    if (psa_hash_update(&ctx->op, data, len) != PSA_SUCCESS) {
        psa_hash_abort(&ctx->op);
    }
}

void bitle_sha256_finish(bitle_sha256_ctx_t *ctx, uint8_t out[32])
{
    size_t olen = 0;
    if (psa_hash_finish(&ctx->op, out, 32, &olen) != PSA_SUCCESS || olen != 32) {
        /* A failed/aborted operation must never yield a digest that could
         * match anything real. */
        memset(out, 0xFF, 32);
        psa_hash_abort(&ctx->op);
    }
}

void bitle_sha256_abort(bitle_sha256_ctx_t *ctx)
{
    psa_hash_abort(&ctx->op);
}

void bitle_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    /* RFC 2104 over the streaming hash: avoids the PSA key store so it works
     * identically on mbedTLS 3.x and 4.x. All firmware keys are <= 64 bytes. */
    uint8_t pad[SHA256_BLOCK];
    uint8_t inner[32];
    if (key_len > SHA256_BLOCK) {
        memset(out, 0xFF, 32);
        return;
    }

    bitle_sha256_ctx_t ctx;
    memset(pad, 0x36, sizeof(pad));
    for (size_t i = 0; i < key_len; ++i) {
        pad[i] ^= key[i];
    }
    bitle_sha256_begin(&ctx);
    bitle_sha256_update(&ctx, pad, sizeof(pad));
    bitle_sha256_update(&ctx, msg, msg_len);
    bitle_sha256_finish(&ctx, inner);

    memset(pad, 0x5C, sizeof(pad));
    for (size_t i = 0; i < key_len; ++i) {
        pad[i] ^= key[i];
    }
    bitle_sha256_begin(&ctx);
    bitle_sha256_update(&ctx, pad, sizeof(pad));
    bitle_sha256_update(&ctx, inner, sizeof(inner));
    bitle_sha256_finish(&ctx, out);
}

esp_err_t bitle_hash_init(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed");
        return ESP_FAIL;
    }

    /* Known-answer test: SHA-256("abc"), FIPS 180-2 appendix B.1. */
    static const uint8_t sha_kat[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t digest[32];
    bitle_sha256((const uint8_t *)"abc", 3, digest);
    if (memcmp(digest, sha_kat, sizeof(sha_kat)) != 0) {
        ESP_LOGE(TAG, "SHA-256 self-test failed");
        return ESP_FAIL;
    }

    /* Known-answer test: HMAC-SHA256, RFC 4231 test case 2. */
    static const uint8_t hmac_kat[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    bitle_hmac_sha256((const uint8_t *)"Jefe", 4,
                      (const uint8_t *)"what do ya want for nothing?", 28, digest);
    if (memcmp(digest, hmac_kat, sizeof(hmac_kat)) != 0) {
        ESP_LOGE(TAG, "HMAC-SHA256 self-test failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "PSA crypto ready (SHA-256/HMAC self-tests passed)");
    return ESP_OK;
}
