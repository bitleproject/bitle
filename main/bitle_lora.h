#ifndef BITLE_LORA_H
#define BITLE_LORA_H

/* LoRa trunk: kilometer-scale node-to-node backhaul.
 *
 * The trunk registers one bitle_link (handle BITLE_LORA_LINK_HANDLE) for
 * the whole medium once an SX1262 is detected, so the mesh core relays
 * BLE<->LoRa with no special cases. Encoded BitChat packets are carried in
 * fragments under a 16-byte trunk header, with per-frame acknowledgement;
 * frames from foreign LoRa protocols fail the magic check and are dropped
 * before touching the mesh.
 *
 * Boards without the radio (every C3, an S3 without the Wio module)
 * probe at boot, find nothing, and run BLE-only — one firmware for all
 * node types.
 */

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITLE_LORA_LINK_HANDLE 0x4000

/* Detects the radio and, if present, brings up the trunk. Never fails
 * the boot: absence of a radio is a supported configuration. */
esp_err_t bitle_lora_init(void);

bool bitle_lora_active(void);

#ifdef __cplusplus
}
#endif

#endif // BITLE_LORA_H
