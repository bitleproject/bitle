# Bitle Over-the-Air Updates

Bitle nodes update their own firmware in the field and gossip new images
to each other across the mesh, so a fleet on a trail can be updated without
retrieving hardware. This document covers the trust model, the one-time
setup, and how to cut and distribute a release.

> **Deploy the OTA-capable image before sealing enclosures.** OTA cannot be
> retrofitted remotely: a node flashed with a single-`factory` partition
> layout has nowhere to stage an update. Flash the dual-slot image
> (this firmware) by wire first; after that, everything is remote.

## Trust model

Every image is authenticated by an **Ed25519 owner key**. The private key
lives offline on your machine and signs releases; only the 32-byte public
key is compiled into the firmware (`main/ota_owner_pubkey.h`). A node:

- verifies the signed manifest before accepting a single byte of an image,
- verifies the SHA-256 of the fully written image before switching to it,
- refuses any version less than or equal to what it runs (no downgrades),
- boots the new image on a **rollback trial**: if it does not prove itself
  healthy (a peer connects and its announce verifies end to end), the
  bootloader automatically reverts to the previous image on the next reset.

Losing the private key means you can never ship another update to deployed
nodes — **back it up**. Compromise of the private key means an attacker can
push firmware to your fleet — **keep it offline**.

## One-time setup

```bash
pip install cryptography
python tools/gen_owner_key.py            # writes ~/bitle-keys/bitle_owner_key.hex
                                         # and main/ota_owner_pubkey.h (commit this)
```

Back up `~/bitle-keys/bitle_owner_key.hex` somewhere safe and offline. Commit
the regenerated `main/ota_owner_pubkey.h`. Do this once, before building the
images you deploy.

## Cutting a release

1. Bump `BITLE_FW_VERSION` in `main/bitle_ota.h` (strictly increasing).
2. Build, then sign the image with the same version number:

   ```bash
   idf.py build
   python tools/sign_fw.py build/bitle.bin --version <N>   # match BITLE_FW_VERSION
   ```

   This writes `build/bitle.bin.bota`, a 110-byte signed manifest that
   travels ahead of the image.

## Distributing a release

**Seeding (getting v_N onto the first node):** push `bitle.bin.bota`
followed by the image to any one node from a BLE-capable tool (a phone app
or laptop script that speaks the four `0xA0`–`0xA3` OTA packet types). That
node verifies, applies, reboots into the new image, and begins advertising
the new version.

**Propagation (the mesh does the rest):** Bitle nodes discover and connect
to each other directly over BLE (they run as BLE central *and* peripheral,
so a node keeps accepting phones while dialing peer nodes — two outbound
peer links max, with slots always reserved for phones). Each node advertises
its firmware version in a private announce TLV (`0xB0`). A node running a
newer image that hears a stale neighbor offers its signed manifest; the
stale node requests chunks and pulls the image node-to-node. A node that
finishes updating stores the manifest and immediately becomes a server
itself, so one seeded node epidemically updates every node it can reach —
no phone required.

> Phones do **not** carry OTA traffic: BitChat drops unknown packet types
> rather than relaying them, so propagation rides Bitle's own node-to-node
> links, not phone bridges.

To let a **wire-flashed** node serve its own running image to peers, flash
the matching manifest into its `fw_manifest` partition:

```bash
python tools/seed_manifest.py <port> build/bitle.bin.bota   # then reset
```

On boot the node verifies the manifest against its own flash and starts
serving. A node that received its image over the air already has the
manifest and serves with no extra step.

## Wire protocol (packet types)

| Type | Name         | Direction        | Payload                                   |
|------|--------------|------------------|-------------------------------------------|
| 0xA0 | OTA_MANIFEST | server → client  | 110-byte signed manifest                  |
| 0xA1 | OTA_REQ      | client → server  | `version(4) chunk_index(4)`               |
| 0xA2 | OTA_CHUNK    | server → client  | `version(4) chunk_index(4) data(≤chunk)`  |
| 0xA3 | OTA_STATUS   | client → server  | `code(1)` (0x00 ok, 0xEx error)           |

Manifest layout: `"BOTA" version(4) size(4) sha256(32) chunk(2) sig(64)`,
all integers big-endian; the signature covers
`"bitle-fw-v1" || version || size || sha256 || chunk`.

Transfers are stop-and-wait with receiver-driven requests and a
resume-on-timeout retry, so a dropped BLE link resumes rather than
restarting.
