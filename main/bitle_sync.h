#ifndef BITLE_SYNC_H
#define BITLE_SYNC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "noise_handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Gossip sync (BitChat requestSync 0x21 + RSR replays).
 *
 * A bounded RAM store of recent public packets lets a passing phone both
 * DEPOSIT what it carries (we ingest its normal floods and RSR replays)
 * and COLLECT what it missed (we answer its GCS filter requests), making
 * the node a dead-drop for public traffic across mesh deserts.
 *
 * Budgets (static allocation only, sized against 154 KB measured free
 * heap): BITLE_SYNC_SLOTS x BITLE_SYNC_FRAME_MAX ~= 42 KB, hard per-type
 * quotas, expired-first-then-oldest eviction. */

#define BITLE_SYNC_SLOTS        80
#define BITLE_SYNC_FRAME_MAX    524
#define BITLE_SYNC_QUOTA_ANNOUNCE 24   /* one per sender, replaced */
#define BITLE_SYNC_QUOTA_MESSAGE  40   /* message + groupMessage */
#define BITLE_SYNC_QUOTA_PREKEY   16   /* one per owner, replaced */

esp_err_t bitle_sync_init(void);

/* Store a public packet (host task; raw = the encoded frame as received).
 * Accepts types announce/message/groupMessage/prekeyBundle only. */
void bitle_sync_ingest(const bitchat_packet_t *packet, const uint8_t *raw, uint16_t raw_len);

/* Handle an inbound 0x21 (noise worker task; identity already resolvable
 * via noise_get_peer_identity). Replays unseen stored packets as RSR. */
void bitle_sync_handle_request(uint16_t conn_handle, const bitchat_packet_t *packet);

/* Periodic driver (noise worker): sends our own signed ttl=0 requestSync
 * to this subscribed peer at most once per minute, so the node PULLS the
 * mesh history a passing phone carries. */
void bitle_sync_tick(uint16_t conn_handle, const uint8_t peer_id[8], uint64_t uptime_ms);

#ifdef __cplusplus
}
#endif

#endif /* BITLE_SYNC_H */
