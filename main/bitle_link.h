#ifndef BITLE_LINK_H
#define BITLE_LINK_H

/* Transport-agnostic link registry.
 *
 * A "link" is any peer connection that can carry encoded BitChat packets:
 * a BLE connection today, a LoRa neighbor tomorrow. Transports register a
 * link when the peer becomes able to receive (BLE: subscribed / CCCD
 * written) and unregister it when the peer goes away. The mesh core
 * (bitle_mesh) relays through this table without knowing what a link is.
 *
 * Handles share one namespace: BLE links use their NimBLE conn handle
 * (small integers); future transports must allocate from a disjoint range
 * (LoRa reserves 0x4000+).
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITLE_LINK_MAX  8
#define BITLE_LINK_NONE 0xFFFF

/* Handles at/above this are broadcast media (the LoRa trunk): one handle
 * fronts many remote peers. A node must NOT run point-to-point rituals —
 * proactive Noise session-init, gossip requestSync — over them; those are
 * for real 1:1 BLE peers. It still relays and answers directed traffic. */
#define BITLE_LINK_BROADCAST_BASE 0x4000
static inline bool bitle_link_is_broadcast(uint16_t handle)
{
    return handle >= BITLE_LINK_BROADCAST_BASE;
}

typedef enum {
    BITLE_LINK_BLE,
    BITLE_LINK_LORA,
} bitle_link_type_t;

typedef int (*bitle_link_send_fn_t)(uint16_t handle, const uint8_t *data, uint16_t len);

esp_err_t bitle_link_init(void);

/* Registers a link as ready to carry packets. Idempotent per handle. */
esp_err_t bitle_link_register(uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn);
void bitle_link_unregister(uint16_t handle);
bool bitle_link_ready(uint16_t handle);

esp_err_t bitle_link_send(uint16_t handle, const uint8_t *data, uint16_t len);

/* Sends to every registered link except exclude_handle (BITLE_LINK_NONE to
 * send to all). Returns the number of links the send succeeded on. */
int bitle_link_broadcast(uint16_t exclude_handle, const uint8_t *data, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif // BITLE_LINK_H
