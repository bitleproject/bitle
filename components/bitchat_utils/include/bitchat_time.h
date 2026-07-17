#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t bitchat_time_init(void);
uint64_t bitchat_time_now_ms(void);
/* Tentative time source (any direct packet): bootstraps the clock before the
 * first sync and applies small forward nudges after, but never makes a large
 * post-sync correction (anti-poisoning). */
void bitchat_time_consider_peer(uint64_t peer_timestamp_ms);
/* Authoritative time source (a verified direct announce). Phones carry no
 * 0xB1 flag (peer_is_infra=false) and are the time authority: they may
 * correct even a wrong, already-synced clock. Another Bitle (infra) may only
 * make a large correction when it is itself phone-authoritative and we are
 * not — this propagates real time hop-by-hop without letting clock-less
 * nodes poison each other. */
void bitchat_time_consider_peer_announce(uint64_t peer_timestamp_ms,
                                         bool peer_is_infra, bool peer_is_authoritative);
/* True when our clock traces (directly or hop-by-hop) to a phone this boot.
 * Advertised in the 0xB1 announce flag so peers can propagate it. */
bool bitchat_time_is_authoritative(void);
bool bitchat_time_is_valid(void);
/* Increments on every peer sync/confirmation; lets senders detect that
 * previously announced timestamps are stale and should be re-sent. */
uint32_t bitchat_time_sync_generation(void);
/* Call periodically; persists the wall-clock estimate so reboots resume
 * from the last known time instead of rewinding. */
void bitchat_time_poll(void);

#ifdef __cplusplus
}
#endif
