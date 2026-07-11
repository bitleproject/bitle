# Bitle v0.1

Bitle is a self-powered ESP32-C3 BitChat relay node. It extends BitChat’s Bluetooth mesh by hosting a dedicated BLE gateway that handles Noise XX handshakes, validates BitChat packets, and re-broadcasts encrypted payloads without user interaction. The current hardware uses an ESP32-C3 with a flexible 2.4 GHz antenna, weatherproof enclosure, solar input, and battery pack. Bitle is well suited to extend the mesh network range in places like remote trails, campsites, or any offline comms grid.

## Features

- **Full BitChat handshake** – Implements the Noise XX pattern with the upstream `noise_ref` library, performing Ed25519 identity binding like the mobile apps.
- **BLE mesh relay** – Runs a NimBLE GATT service that BitChat clients subscribe to; packets are encoded/decoded with the BitChat binary format and forwarded transparently.
- **Time sync & nicknames** – Maintains a BLE-derived epoch for packet timestamps and advertises deterministic `Bitle-####` nicknames (configurable through NVS).
- **Ready for solar/battery deployments** – Firmware is autonomous; once flashed it will advertise, accept connections, and keep the mesh alive indefinitely.

## Repository layout

```
├── CMakeLists.txt        # ESP-IDF project entry
├── sdkconfig.defaults   # Recommended configuration seed
├── components/
│   ├── bitchat_utils/   # Time sync helper used by the firmware
│   └── noise_ref/       # Bundled Noise-C reference library
└── main/
    ├── main.c
    ├── bitchat_ble.{c,h}
    ├── noise_handshake.{c,h}
    ├── packet_codec.{c,h}
    └── nickname_manager.{c,h}
```

## Building & flashing

The firmware has been developed and tested with **ESP-IDF v6.0**, though other recent 5.x/6.x releases should also work.

### Prerequisites

- ESP-IDF installed (recommended: `~/esp-idf`)
- Toolchain exported in the current shell before running build commands:

```bash
source ~/esp-idf/export.sh
```

```bash
idf.py set-target esp32c3
idf.py build
idf.py -p /dev/cu.usbmodem101 flash monitor
```

Adjust the serial port (`-p`) for your setup. `sdkconfig` will be generated from `sdkconfig.defaults` during the first build.

## Firmware updates & owner key

Bitle supports signed, mesh-propagating over-the-air (OTA) updates, so nodes already deployed in the field can be upgraded without physical access. The full design — dual-slot A/B rollback, Ed25519-signed manifests, and node-to-node propagation — is documented in [docs/OTA.md](docs/OTA.md).

Trust is anchored by a single **owner key**. Each node ships trusting one Ed25519 public key, baked into `main/ota_owner_pubkey.h`; only the holder of the matching private key can sign an image the fleet will accept. That private key lives outside the repo (by default `~/bitle-keys/bitle_owner_key.hex`) and is never committed.

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
- `components/noise_ref`: Noise-C reference library (MIT-style). Review the upstream license before redistribution.

---

For field deployment, drop the firmware onto an ESP32-C3 in your Bitle enclosure, connect power, and the node will immediately begin extending nearby BitChat meshes.

