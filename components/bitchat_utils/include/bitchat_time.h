#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t bitchat_time_init(void);
uint64_t bitchat_time_now_ms(void);
void bitchat_time_consider_peer(uint64_t peer_timestamp_ms);
void bitchat_time_set_from_wall(uint64_t unix_ms);
bool bitchat_time_is_valid(void);
/* True once the clock has been synced or confirmed by a peer this boot. */
bool bitchat_time_is_peer_synced(void);
/* Increments on every peer sync/confirmation; lets senders detect that
 * previously announced timestamps are stale and should be re-sent. */
uint32_t bitchat_time_sync_generation(void);
/* Call periodically; persists the wall-clock estimate so reboots resume
 * from the last known time instead of rewinding. */
void bitchat_time_poll(void);

#ifdef __cplusplus
}
#endif
