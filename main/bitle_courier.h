#ifndef BITLE_COURIER_H
#define BITLE_COURIER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Store-and-forward courier mailbox (BitChat packet type 0x04).
 *
 * Phones deposit end-to-end-encrypted envelopes with any announce-verified
 * peer when the recipient is unreachable; this node accepts such deposits,
 * keeps them in the flash mailbox, and hands them over when the recipient
 * (matched by rotating HMAC tag) or another carrier appears. Envelopes are
 * opaque ciphertext — the relay can never read them.
 *
 * Budgets: at most BITLE_COURIER_MAX_ENVELOPES stored (inside the flash
 * ring's own cap), at most BITLE_COURIER_MAX_PER_DEPOSITOR from any one
 * peer, envelope lifetime capped at 25 h (mirrors upstream slack). */

#define BITLE_COURIER_MAX_ENVELOPES      128
#define BITLE_COURIER_MAX_PER_DEPOSITOR  8

esp_err_t bitle_courier_init(void);

/* Deposit handler; called on the noise worker task with the depositor's
 * link identity already resolved. Returns true if stored. */
bool bitle_courier_accept(uint16_t conn_handle, const uint8_t depositor[8],
                          bool depositor_verified, const uint8_t *payload,
                          uint16_t payload_len, uint64_t now_ms);

/* Announce hook: delivers matching mail to the tag owner (direct announce),
 * sprays multi-copy envelopes to other verified carriers, and floods a
 * single copy toward owners heard through the mesh (relayed announce). */
void bitle_courier_peer_announced(uint16_t conn_handle, const uint8_t peer_id[8],
                                  const uint8_t noise_key[32], bool verified,
                                  bool is_direct, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* BITLE_COURIER_H */
