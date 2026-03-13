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

#ifdef __cplusplus
}
#endif
