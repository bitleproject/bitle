#!/usr/bin/env python3
"""Flash a Bitle release manifest into a node's fw_manifest partition.

After `idf.py flash`, the node runs the release but cannot serve it to peers
until it holds the signed manifest. This writes the 110-byte .bota manifest
to the fw_manifest partition (offset 0x12000); on next boot the node verifies
it against its own flash and starts serving. Pad to the 4 KB flash sector.

Usage:
    python tools/seed_manifest.py <port> build/bitle.bin.bota
"""

import os
import subprocess
import sys
import tempfile

MANIFEST_OFFSET = 0x12000
SECTOR = 0x1000


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 1
    port, manifest_path = sys.argv[1], sys.argv[2]

    with open(manifest_path, "rb") as f:
        manifest = f.read()
    if len(manifest) != 110 or manifest[:4] != b"BOTA":
        print("Not a .bota manifest", file=sys.stderr)
        return 1

    padded = manifest + b"\xff" * (SECTOR - len(manifest))
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(padded)
        tmp_path = tmp.name
    try:
        cmd = [
            sys.executable, "-m", "esptool", "--chip", "esp32c3", "-p", port,
            "write_flash", hex(MANIFEST_OFFSET), tmp_path,
        ]
        print("+", " ".join(cmd))
        rc = subprocess.call(cmd)
    finally:
        os.unlink(tmp_path)
    if rc == 0:
        print(f"Manifest written at {hex(MANIFEST_OFFSET)}; reset the node to adopt it.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
