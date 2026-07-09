#!/usr/bin/env python3
"""Sign a Bitle firmware image for OTA distribution.

Produces <image>.bota - a 110-byte manifest that travels ahead of the image:

    magic   "BOTA"            4 bytes
    version u32 BE            4 bytes   (monotonic build number)
    size    u32 BE            4 bytes   (image length in bytes)
    sha256                    32 bytes  (of the raw image)
    chunk   u16 BE            2 bytes   (chunk payload size)
    sig     Ed25519           64 bytes  (over "bitle-fw-v1" || version || size || sha256 || chunk)

Usage:
    python tools/sign_fw.py build/bitle.bin --version 2 \
        [--key ~/bitle-keys/bitle_owner_key.hex] [--chunk-size 384]
"""

import argparse
import hashlib
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAGIC = b"BOTA"
SIGN_CONTEXT = b"bitle-fw-v1"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="firmware .bin to sign")
    parser.add_argument("--version", type=int, required=True, help="monotonic firmware version number")
    parser.add_argument("--key", default=os.path.expanduser("~/bitle-keys/bitle_owner_key.hex"))
    parser.add_argument("--chunk-size", type=int, default=384)
    args = parser.parse_args()

    if not 0 < args.version < 2**32:
        print("version must fit in u32", file=sys.stderr)
        return 1
    if not 64 <= args.chunk_size <= 480:
        print("chunk-size must be 64..480", file=sys.stderr)
        return 1

    with open(args.key, "r", encoding="ascii") as f:
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))

    with open(args.image, "rb") as f:
        image = f.read()

    digest = hashlib.sha256(image).digest()
    fields = struct.pack(">II", args.version, len(image)) + digest + struct.pack(">H", args.chunk_size)
    signature = key.sign(SIGN_CONTEXT + fields)
    manifest = MAGIC + fields + signature

    out_path = args.image + ".bota"
    with open(out_path, "wb") as f:
        f.write(manifest)

    print(f"Signed {args.image} ({len(image)} bytes, sha256 {digest.hex()[:16]}...)")
    print(f"Manifest: {out_path} (version {args.version}, chunk {args.chunk_size})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
