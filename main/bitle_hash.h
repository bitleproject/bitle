#ifndef BITLE_HASH_H
#define BITLE_HASH_H

/* SHA-256 / HMAC-SHA256 via the PSA Crypto API.
 *
 * ESP-IDF v6.0 releases ship mbedTLS 4.x (TF-PSA-Crypto), which removed the
 * legacy mbedtls/sha256.h and mbedtls/md.h APIs; PSA is the one interface
 * present in both mbedTLS 3.x and 4.x, so all firmware hashing goes through
 * this shim instead of mbedtls directly. bitle_hash_init() also runs known-
 * answer self-tests so a broken crypto port can never boot quietly.
 */

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    psa_hash_operation_t op;
} bitle_sha256_ctx_t;

/* psa_crypto_init() + SHA-256/HMAC known-answer tests. Call once at boot
 * before any subsystem that hashes (noise, ota, sync, courier). */
esp_err_t bitle_hash_init(void);

void bitle_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

void bitle_sha256_begin(bitle_sha256_ctx_t *ctx);
void bitle_sha256_update(bitle_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
/* Writes the digest; on internal PSA failure fills out with 0xFF so a bad
 * digest can never accidentally match an expected hash. */
void bitle_sha256_finish(bitle_sha256_ctx_t *ctx, uint8_t out[32]);
/* Releases a begun-but-unfinished context (abort/error paths). */
void bitle_sha256_abort(bitle_sha256_ctx_t *ctx);

/* HMAC-SHA256, keys up to 64 bytes (block-sized). */
void bitle_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif // BITLE_HASH_H
