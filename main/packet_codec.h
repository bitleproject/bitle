#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


#include "noise_handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

bool bitchat_packet_decode(const uint8_t *data, size_t len, bitchat_packet_t *out_packet);
bool bitchat_packet_encode(const bitchat_packet_t *packet, uint8_t *out_buf, size_t *out_len, size_t max_len);
void bitchat_packet_free(bitchat_packet_t *packet);
bool packet_codec_self_test(void);

#ifdef __cplusplus
}
#endif

#endif // PACKET_CODEC_H

