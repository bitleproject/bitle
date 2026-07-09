#ifndef BITLE_OTA_H
#define BITLE_OTA_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "noise_handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Monotonic firmware version. Bump on every release and pass the same
 * number to tools/sign_fw.py --version. Nodes only accept higher versions. */
#define BITLE_FW_VERSION 3

esp_err_t bitle_ota_init(void);

/* Feed OTA packets (types 0xA0-0xA3) from the BLE dispatch. Safe to call
 * from the NimBLE host task; work is marshalled onto the OTA task. */
void bitle_ota_handle_packet(uint16_t conn_handle, const bitchat_packet_t *packet);

/* A peer announced this firmware version (0 when its announce had none).
 * Offers our image if we can serve and the peer is behind. */
void bitle_ota_peer_version_seen(uint16_t conn_handle, const uint8_t peer_id[8], uint32_t version);

/* Strong health signal for rollback: call once the new image has proven
 * itself (e.g. first verified announce decoded end-to-end). */
void bitle_ota_mark_healthy(void);

/* True when this node holds a stored, signed manifest matching its running
 * image and can therefore serve the image to stale peers. */
bool bitle_ota_can_serve(void);

/* True while an OTA transfer (either direction) is in flight. */
bool bitle_ota_busy(void);

#ifdef __cplusplus
}
#endif

#endif /* BITLE_OTA_H */
