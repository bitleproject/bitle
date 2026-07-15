# Bitle

Bitle is an autonomous ESP32-C3 BitChat mesh relay node. Once flashed, it needs no phone and no user interaction: it advertises over BLE, completes Noise XX handshakes, validates and re-broadcasts BitChat packets, carries store-and-forward courier mail for offline recipients, gossip-syncs recent public traffic with peers, and self-propagates signed firmware updates node-to-node. It is well suited to extending a BitChat mesh in places like remote trails, campsites, or any offline comms grid, and is designed for solar/battery deployments where the enclosure is sealed and never touched again.

The reference hardware pairs an ESP32-C3 with a flexible 2.4 GHz antenna, a weatherproof enclosure, solar input, and a battery pack. The firmware is developed and tested on ESP-IDF v6.0 and runs unmodified on both the `esp32c3` and `esp32s3` targets — the same source powers XIAO ESP32C3 nodes and the XIAO ESP32S3 (the platform for upcoming LoRa backhaul work).

## What it does

A single node runs a genuinely simultaneous **dual-role BLE stack** on NimBLE. It advertises a connectable BitChat GATT peripheral so phones can subscribe, while a periodic central scanner discovers and dials *other Bitle nodes* — so one node holds links to phones **and** other Bitles at the same time. Out of a 6-connection budget it dials at most 2 outbound node-to-node links and keeps at least 2 slots reserved for inbound phones. This lets the mesh propagate across gaps with no phone in the path.

## Features

- **Full BitChat handshake.** Implements the Noise XX pattern (`Noise_XX_25519_ChaChaPoly_SHA256`) via the bundled `noise_ref` (Noise-C) reference library, with Ed25519 identity binding like the mobile apps. Each node persists a Curve25519 static keypair and an Ed25519 signing keypair in NVS; its 8-byte peer ID is the first 8 bytes of SHA-256 over its Noise static public key.

- **Signed identity announces.** Identity rides in a signed `ANNOUNCE` (type `0x01`) carrying TLVs for nickname, Noise static key, and Ed25519 signing key, plus two Bitle-private TLVs: firmware version (`0xB0`) and role/authority flags (`0xB1`). A legacy `0x13` identity-announce is still emitted best-effort for older clients. Inbound announces are hard-rejected unless the sender ID equals SHA-256(announced Noise key)[0:8].

- **Dual-role BLE mesh relay.** Packets are encoded/decoded with the BitChat binary format and relayed to every other subscribed link. Relay is TTL-based (packets with `ttl <= 1` are dropped, otherwise the TTL byte is decremented before rebroadcast) and de-duplicated with an FNV-1a fingerprint over the packet bytes (skipping the TTL byte) kept in a 64-entry ring. Own echoes, `REQUEST_SYNC`, packets addressed to this node, and undirected Noise handshakes are never relayed. Phone-fragmented packets are reassembled in a small bounded pool (2 slots, up to 4 parts × 250 bytes, 15 s timeout); anything larger is forwarded relay-only. Max handled BLE packet size is 520 bytes. A 30 s subscribe watchdog drops links that connect but never enable notifications, and a short deny/cool-down list prevents immediately re-dialing a just-dropped peer.

- **Store-and-forward courier mailbox.** Accepts BitChat `CourierEnvelope` packets (type `0x04`) that phones deposit for offline recipients, stores them as opaque ciphertext keyed by SHA-256(ciphertext), and hands them over when the recipient — matched by a daily-rotating HMAC recipient tag — or another carrier later announces. The relay never learns envelope contents. Deposits are only accepted over a direct Noise link from a signature-verified, identity-verified sender. Budgets are enforced structurally: at most 128 envelopes, at most 8 per depositor, a 25 h lifetime cap, and a flash sector-ring that erases its oldest sector before it can overrun the partition.

- **Gossip sync (dead-drop).** Keeps a small, RAM-bounded store (up to 80 recent *signed* public packets: announces, direct/group messages, prekey bundles) and reconciles it with peers using a Golomb-Rice/GCS set filter built to be bit-exact with upstream BitChat. When a phone subscribes, the node both answers the phone's `requestSync` (type `0x21`) by replaying packets it is missing (flagged RSR, TTL forced to 0) and pulls the phone's history by sending its own signed `requestSync`, at most once per peer per minute. Requests are gated (TTL 0, verified peer, rate-limited *before* signature verification), and eviction is expired-first then oldest-by-local-receive-order, so a flood of attacker-timestamped packets cannot evict legitimate data.

- **Signed, mesh-propagating OTA with dual-slot rollback.** Deployed nodes update themselves and gossip new images node-to-node over BLE, no phone in the transfer path. Every image is authenticated by a single offline Ed25519 owner key before any byte is accepted, written to an ESP-IDF A/B slot, and re-verified by SHA-256 before the boot slot is switched. New images boot on a bootloader rollback trial that is only cancelled once the radio and crypto prove healthy (a peer's announce verifies end-to-end) or a 30-minute fallback elapses. See [docs/OTA.md](docs/OTA.md) and the [owner key](#firmware-updates--owner-key) section below.

- **BLE-derived clock with phone-authoritative time.** Bitle has no RTC. Wall-clock time is reconstructed as a persisted epoch base (seeded from the firmware build timestamp, never earlier) plus the ESP32 monotonic timer, then corrected from timestamps harvested *only* from directly-connected peers (relayed/replayed timestamps are ignored). A two-bit authority model (announce TLV `0xB1`) ranks sources: phones are the top authority and may correct even an already-synced clock, while relay nodes only carry real time forward once they themselves trace to a phone. An anti-poison anchor caps forward drift to real-time speed, a 30 s skew window keeps the clock well inside the ±120 s window iOS accepts, and the estimate is persisted to NVS so reboots resume from the last known time instead of rewinding by uptime.

- **Deterministic `Bitle-####` nicknames.** On first boot a node derives a display nickname of the form `Bitle-####` (four decimal digits, mod 10000) from its own peer ID, and carries it in identity announces. A custom 1–31-char printable-ASCII name written to NVS is honored verbatim; a legacy `anon####` name is migrated to the branded form without touching the identity keypair. Note: the suffix is only four digits, so nicknames are not guaranteed unique across nodes. There is currently no wired-up runtime command to set or regenerate a nickname — custom names must be provisioned by writing the NVS `nickname` key directly.

- **Autonomous by design.** Once flashed the firmware advertises, accepts connections, relays, and keeps the mesh alive indefinitely with no supervision. Direct messages addressed to the node get a delivery ack and exactly one canned auto-reply per session (identifying Bitle as a relay and citing bitle.org); a chatty sender cannot cause ping-pong.

> **Note on the BLE advertised name.** The BLE device name is the fixed literal `Bitle Relay` (that exact string is how the central scanner recognises other nodes). The `Bitle-####` value is an app-layer BitChat nickname, not the BLE advertising name.

## Boot sequence

`app_main()` runs a fixed init order: NVS → PSA crypto (with SHA-256/HMAC known-answer self-tests) → time → Noise → OTA → sync → courier → packet codec (with self-test) → BLE init → BLE start, then spawns a single `bitle_main` FreeRTOS task that polls BLE, Noise, and the clock every 50 ms. Most init steps are fatal on failure (`ESP_ERROR_CHECK` / `abort`); the courier mailbox is the one optional subsystem — if it can't start, the node logs a warning and continues without store-and-forward. If NVS reports a layout/version change, the flash is erased and re-initialized rather than bricking boot.

## Repository layout

```
├── CMakeLists.txt              # ESP-IDF project entry
├── partitions.csv              # 4 MB OTA + msgstore layout
├── sdkconfig.defaults          # configuration seed
├── .github/workflows/ci.yml    # CI
├── components/
│   ├── bitchat_utils/          # bitchat_time: BLE-derived clock w/ authority tiers
│   └── noise_ref/              # vendored Noise-C reference library (~97 files)
├── docs/OTA.md                 # full OTA + node-to-node design
├── tools/
│   ├── gen_owner_key.py        # generate owner signing keypair + pubkey header
│   ├── sign_fw.py              # sign a firmware image -> manifest
│   ├── seed_manifest.py        # write manifest into fw_manifest partition
│   └── courier_test.py         # BLE courier test harness (bleak + Ed25519)
└── main/
    ├── main.c
    ├── bitchat_ble.{c,h}       # dual-role BLE (peripheral + central), relay, fragments
    ├── noise_handshake.{c,h}   # Noise XX, announce TLVs, message dispatch
    ├── packet_codec.{c,h}      # BitChat binary packet encode/decode
    ├── bitle_hash.{c,h}        # SHA-256/HMAC via PSA (mbedTLS 3.x & 4.x compatible)
    ├── bitle_ota.{c,h}         # dual-slot OTA, signed manifests
    ├── ota_owner_pubkey.h      # baked-in owner public key (generated)
    ├── bitle_courier.{c,h}     # store-and-forward courier mailbox
    ├── bitle_store.{c,h}       # flash sector-ring persistence (msgstore)
    ├── bitle_sync.{c,h}        # gossip sync (GCS / requestSync)
    └── nickname_manager.{c,h}  # deterministic Bitle-#### nicknames
```

`components/noise_ref` is a self-contained vendored third-party library, not Bitle-authored code.

## Flash & partition layout

The build seeds a **4 MB** flash with a custom partition table (`partitions.csv`), enables bootloader app rollback (trial boot with automatic revert), and uses NimBLE (Bluedroid disabled) in both central and peripheral roles. The layout is:

| Partition | Purpose |
| --- | --- |
| `nvs` (24 K) | keys, nickname, persisted clock estimate |
| `phy_init` (4 K) | RF calibration |
| `otadata` (8 K) | A/B boot selection |
| `fw_manifest` (4 K, subtype `0x40`) | 110-byte signed OTA manifest |
| `ota_0` / `ota_1` (`0x1C0000` each) | dual-slot A/B application images |
| `msgstore` (384 K, subtype `0x41`) | courier mailbox sector-ring |

Because OTA relies on this dual-slot layout, **nodes must be wire-flashed with this partition table before their enclosures are sealed** — the A/B capability cannot be retrofitted remotely.

## Building & flashing

The firmware is developed and tested with **ESP-IDF v6.0** and supports the **`esp32c3`** and **`esp32s3`** targets — both validated on hardware (Seeed XIAO ESP32C3 and XIAO ESP32S3). All hashing goes through the PSA Crypto API, so it builds against both mbedTLS 3.x (v6.0 pre-release snapshots) and mbedTLS 4.x (v6.0 release line, which removed the legacy `mbedtls/sha256.h` API). The component manifest floors at IDF `>=5.0`, but v6.0 is what is actually built and tested.

### Prerequisites

- ESP-IDF installed (recommended: `~/esp-idf`)
- Toolchain exported in the current shell before building:

```bash
source ~/esp-idf/export.sh
```

### Build

```bash
idf.py set-target esp32c3   # or esp32s3
idf.py build
idf.py -p /dev/cu.usbmodem101 flash monitor
```

Adjust the serial port (`-p`) for your setup. `sdkconfig` is generated from `sdkconfig.defaults` on the first build.

## Firmware updates & owner key

Bitle supports signed, mesh-propagating over-the-air (OTA) updates, so nodes already deployed in the field can be upgraded without physical access. The full design — dual-slot A/B rollback, Ed25519-signed manifests, the health-signal rollback trial, and node-to-node propagation — is documented in [docs/OTA.md](docs/OTA.md).

How propagation works, briefly: each node advertises an internal firmware version in announce TLV `0xB0`. This version is `BITLE_FW_VERSION` (currently **4**) — a monotonic OTA *update counter* used only for version comparison, **not** a product/marketing release number; nodes only accept strictly-higher versions and refuse downgrades. A node holding a signed manifest that matches its own running image offers it to any stale peer it sees (rate-limited to once per minute per link); the peer then pulls chunks as directed BitChat packets (types `0xA0`–`0xA3`), with authenticity guaranteed by the signed manifest and a full-image SHA-256 check rather than transport encryption, via a receiver-driven stop-and-wait protocol that resumes rather than restarts after a stall. Even a wire-flashed node can become a server by adopting a signed manifest from the `fw_manifest` partition (`tools/seed_manifest.py`).

Trust is anchored by a single **owner key**. Each node ships trusting one Ed25519 public key, baked into `main/ota_owner_pubkey.h`; only the holder of the matching private key can sign an image the fleet will accept. The image is verified against that key before any byte is written, and the assembled image's SHA-256 is re-checked before the boot slot is switched. The private key lives outside the repo (by default `~/bitle-keys/bitle_owner_key.hex`) and is never committed.

> **Running your own independent fleet?** The public key committed here belongs to the Bitle project, so nodes you flash from this repo unmodified will trust *official* Bitle firmware releases. If you are deploying a fleet you alone control, generate your own key pair first and rebuild:
>
> ```bash
> python tools/gen_owner_key.py   # writes ~/bitle-keys/bitle_owner_key.hex (private) and regenerates main/ota_owner_pubkey.h (public)
> ```
>
> Keep the private key offline and backed up: **losing it** means you can never OTA-update your deployed nodes again, and **leaking it** lets an attacker sign firmware for every node that trusts it.

## License

This project is licensed under the [MIT License](LICENSE).  
You are free to use, modify, and distribute this software, provided that attribution is given to the original author.

- Firmware source: © 2025 Mark Soares, released under the MIT License.  
- `components/noise_ref`: Noise-C reference library (MIT-style), vendored into this repo. Review the upstream license before redistribution.

---

For field deployment, drop the firmware onto an ESP32-C3 in your Bitle enclosure, connect power, and the node will immediately begin extending nearby BitChat meshes — relaying live traffic, carrying mail for offline peers, and keeping itself up to date on its own.