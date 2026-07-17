#ifndef BITLE_MESH_H
#define BITLE_MESH_H

/* Transport-agnostic mesh core: packet dispatch, fragment reassembly,
 * dedup, and TTL relay. Transports (BLE and the LoRa trunk) feed every
 * complete inbound packet here; relaying goes back out through the
 * bitle_link registry to every other ready link, regardless of medium.
 *
 * bitle_mesh_inbound is safe to call from multiple tasks: the whole
 * inbound path (dispatch, fragment pool, dedup ring, sync ingest, relay)
 * is serialized by an internal mutex, preserving the single-task
 * semantics the mesh logic was written under.
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t bitle_mesh_init(void);

/* Decodes, dispatches locally, ingests for gossip sync, and relays one
 * inbound packet. buffer must hold the full encoded packet and be
 * writable (the relay path rewrites the TTL byte in place). Returns
 * false if the bytes do not decode as a BitChat packet. */
bool bitle_mesh_inbound(uint16_t link_handle, uint8_t *buffer, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif // BITLE_MESH_H
