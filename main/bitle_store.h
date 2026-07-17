#ifndef BITLE_STORE_H
#define BITLE_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Durable store-and-forward mailbox backed by the msgstore flash partition.
 *
 * Records are opaque byte blobs (fully encoded packets) keyed by a 16-byte
 * identifier, with an absolute expiry. The partition is written as a
 * sector-aligned ring so flash wear stays even; individual records are
 * tombstoned in place (a 0xFF->0x00 program needs no erase).
 *
 * Hard budgets, enforced on every insert:
 *   - record payload <= BITLE_STORE_PAYLOAD_MAX bytes
 *   - at most BITLE_STORE_MAX_RECORDS live records
 *   - never grows past the partition; the oldest sector is reclaimed first
 */

#define BITLE_STORE_KEY_LEN      16
#define BITLE_STORE_PAYLOAD_MAX  520
#define BITLE_STORE_MAX_RECORDS  256

typedef bool (*bitle_store_iter_cb)(const uint8_t key[BITLE_STORE_KEY_LEN],
                                    uint32_t expiry_unix_s, uint8_t flags,
                                    const uint8_t *payload, uint16_t payload_len,
                                    void *arg);

esp_err_t bitle_store_init(void);

/* Inserts (or refreshes) a record. Duplicate keys are tombstoned first.
 * Returns ESP_ERR_INVALID_ARG for an oversize payload and ESP_ERR_NO_MEM
 * when no sector can be reclaimed to make room. */
esp_err_t bitle_store_put(const uint8_t key[BITLE_STORE_KEY_LEN],
                          uint32_t expiry_unix_s, uint8_t flags,
                          const uint8_t *payload, uint16_t payload_len);

/* Calls cb for every live, unexpired record; stop early by returning false. */
void bitle_store_iterate(bitle_store_iter_cb cb, void *arg);

/* Tombstones a record. No-op if absent. */
void bitle_store_delete(const uint8_t key[BITLE_STORE_KEY_LEN]);

bool bitle_store_contains(const uint8_t key[BITLE_STORE_KEY_LEN]);
size_t bitle_store_count(void);

#ifdef __cplusplus
}
#endif

#endif /* BITLE_STORE_H */
