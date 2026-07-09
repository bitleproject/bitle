#!/usr/bin/env python3
"""Generate the Bitle owner signing keypair.

The private key authorizes firmware updates for every node in the field —
keep it offline and backed up. Only the public key is baked into firmware.

Usage:
    python tools/gen_owner_key.py [--out-dir ~/bitle-keys]

Writes:
    <out-dir>/bitle_owner_key.hex   (PRIVATE - never commit, never lose)
    main/ota_owner_pubkey.h         (public key header, committed)
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HEADER_TEMPLATE = """\
/* Bitle OTA owner public key (Ed25519).
 *
 * Firmware updates must be signed by the matching private key
 * (tools/gen_owner_key.py + tools/sign_fw.py). Generated file - do not
 * edit by hand; regenerate to rotate the owner key.
 */
#pragma once

#include <stdint.h>

static const uint8_t BITLE_OTA_OWNER_PUBKEY[32] = {
{rows}
};
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=os.path.expanduser("~/bitle-keys"))
    parser.add_argument("--force", action="store_true", help="overwrite an existing private key")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    priv_path = os.path.join(args.out_dir, "bitle_owner_key.hex")
    if os.path.exists(priv_path) and not args.force:
        print(f"Refusing to overwrite existing key {priv_path} (use --force)", file=sys.stderr)
        return 1

    key = Ed25519PrivateKey.generate()
    priv_raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    with open(priv_path, "w", encoding="ascii") as f:
        f.write(priv_raw.hex() + "\n")
    os.chmod(priv_path, 0o600)

    rows = []
    for i in range(0, 32, 8):
        row = ", ".join(f"0x{b:02x}" for b in pub_raw[i:i + 8])
        rows.append(f"    {row},")
    header = HEADER_TEMPLATE.replace("{rows}", "\n".join(rows))
    header_path = os.path.join(REPO_ROOT, "main", "ota_owner_pubkey.h")
    with open(header_path, "w", encoding="ascii") as f:
        f.write(header)

    print(f"Private key : {priv_path}  (BACK THIS UP - it authorizes all field updates)")
    print(f"Public key  : {header_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
