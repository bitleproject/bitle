#!/usr/bin/env python3
"""Deterministic BLE test of a Bitle node's courier mailbox.

Plays a BitChat client with two protocol identities on one BLE link:
  1. Depositor D sends a signed announce (Bitle verifies + trusts it), then a
     signed CourierEnvelope (0x04) addressed to the Bitle, tagged for R.
  2. Recipient R sends a signed announce; the Bitle matches the stored tag to
     R's noise key and hands the envelope back over the same link.

A received 0x04 whose ciphertext matches what we deposited proves the Bitle's
accept -> store -> tag-match -> hand-off path, with no dependence on a phone's
delivery heuristics. Envelope ciphertext is opaque to the relay, so we use
random bytes (the Bitle never decrypts it).

Usage:  python tools/courier_test.py            # auto-scan for "Bitle Relay"
        python tools/courier_test.py <BLE-UUID> # target a specific device
"""

import asyncio
import hashlib
import hmac
import os
import struct
import sys
import time

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
CHAR_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
DEVICE_NAME = "Bitle Relay"

MSG_ANNOUNCE = 0x01
MSG_COURIER = 0x04
TAG_CONTEXT = b"bitchat-courier-tag-v1"
PAD_BLOCKS = (256, 512, 1024, 2048)


def raw_pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)


class Identity:
    def __init__(self, nickname):
        self.nickname = nickname
        self.sign = Ed25519PrivateKey.generate()
        self.noise = X25519PrivateKey.generate()
        self.sign_pub = raw_pub(self.sign)
        self.noise_pub = raw_pub(self.noise)
        # Peer ID = first 8 bytes of SHA-256(noise static public key).
        self.peer_id = hashlib.sha256(self.noise_pub).digest()[:8]

    def announce_payload(self):
        p = bytearray()
        nick = self.nickname.encode()
        p += bytes([0x01, len(nick)]) + nick
        p += bytes([0x02, len(self.noise_pub)]) + self.noise_pub
        p += bytes([0x03, len(self.sign_pub)]) + self.sign_pub
        return bytes(p)


def optimal_block(n):
    total = n + 16
    for b in PAD_BLOCKS:
        if total <= b:
            return b
    return 0


def canonical(version, mtype, timestamp_ms, sender, recipient, payload):
    """Padded canonical bytes the packet signature covers (ttl=0, no sig)."""
    h = bytearray()
    h += bytes([version, mtype, 0])              # version, type, ttl=0
    h += struct.pack(">Q", timestamp_ms)         # timestamp BE
    flags = 0x01 if recipient else 0x00
    h += bytes([flags])
    h += struct.pack(">H", len(payload))
    h += sender
    if recipient:
        h += recipient
    h += payload
    block = optimal_block(len(h))
    if block and len(h) < block and (block - len(h)) <= 255:
        pad = block - len(h)
        h += bytes([pad]) * pad
    return bytes(h)


def encode_signed(ident, mtype, recipient, payload, ttl=7):
    ts = int(time.time() * 1000)
    sig = ident.sign.sign(canonical(1, mtype, ts, ident.peer_id, recipient, payload))
    out = bytearray()
    out += bytes([1, mtype, ttl])
    out += struct.pack(">Q", ts)
    flags = 0x02                                  # has_signature
    if recipient:
        flags |= 0x01
    out += bytes([flags])
    out += struct.pack(">H", len(payload))
    out += ident.peer_id
    if recipient:
        out += recipient
    out += payload
    out += sig
    return bytes(out)


def courier_tag(recipient_noise_pub, when=None):
    day = int((when or time.time()) // 86400)
    msg = TAG_CONTEXT + struct.pack(">I", day)
    return hmac.new(recipient_noise_pub, msg, hashlib.sha256).digest()[:16]


def envelope_payload(recipient_noise_pub, ciphertext):
    tag = courier_tag(recipient_noise_pub)
    expiry_ms = int((time.time() + 3600) * 1000)
    p = bytearray()
    p += bytes([0x01]) + struct.pack(">H", 16) + tag
    p += bytes([0x02]) + struct.pack(">H", 8) + struct.pack(">Q", expiry_ms)
    p += bytes([0x03]) + struct.pack(">H", len(ciphertext)) + ciphertext
    return bytes(p), tag


def decode_header(data):
    if len(data) < 21:
        return None
    version, mtype, ttl = data[0], data[1], data[2]
    ts = struct.unpack(">Q", data[3:11])[0]
    flags = data[11]
    plen = struct.unpack(">H", data[12:14])[0]
    off = 14
    sender = data[off:off + 8]; off += 8
    recipient = None
    if flags & 0x01:
        recipient = data[off:off + 8]; off += 8
    payload = data[off:off + plen]; off += plen
    return dict(type=mtype, ttl=ttl, sender=sender, recipient=recipient,
                payload=payload, flags=flags)


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target:
        print(f"Scanning for '{DEVICE_NAME}' …")
        dev = await BleakScanner.find_device_by_filter(
            lambda d, ad: (ad.local_name == DEVICE_NAME) or
                          (SERVICE_UUID in (ad.service_uuids or [])), timeout=15)
        if not dev:
            print("FAIL: no Bitle found in range"); return 1
        target = dev.address
        print(f"Found Bitle at {target}")

    depositor = Identity("harness-D")
    recipient = Identity("harness-R")
    ciphertext = os.urandom(48)
    env_payload, tag = envelope_payload(recipient.noise_pub, ciphertext)

    state = {"bitle_peer": None, "handoff": None}

    def on_notify(_char, data):
        hdr = decode_header(bytes(data))
        if not hdr:
            return
        if hdr["type"] == MSG_ANNOUNCE and state["bitle_peer"] is None:
            state["bitle_peer"] = hdr["sender"]
            print(f"  <- Bitle announce; peer_id={hdr['sender'].hex()}")
        elif hdr["type"] == MSG_COURIER and hdr["recipient"] == recipient.peer_id:
            state["handoff"] = hdr["payload"]
            print(f"  <- 0x04 courier hand-off ({len(hdr['payload'])} B)")

    async with BleakClient(target) as client:
        print(f"Connected (mtu={client.mtu_size}). Subscribing…")
        await client.start_notify(CHAR_UUID, on_notify)

        # Learn the Bitle's peer ID from its announce.
        for _ in range(30):
            if state["bitle_peer"]:
                break
            await asyncio.sleep(0.5)
        if not state["bitle_peer"]:
            print("FAIL: never heard the Bitle's announce"); return 1
        bitle = state["bitle_peer"]

        async def send(pkt):
            await client.write_gatt_char(CHAR_UUID, pkt, response=False)
            await asyncio.sleep(0.4)

        print("-> D announce (establish verified courier identity)")
        await send(encode_signed(depositor, MSG_ANNOUNCE, None, depositor.announce_payload()))
        await asyncio.sleep(1.0)

        print(f"-> D deposits envelope tagged {tag.hex()[:16]}… for R")
        await send(encode_signed(depositor, MSG_COURIER, bitle, env_payload))
        await asyncio.sleep(1.5)

        print("-> R announce (should trigger tag-matched hand-off)")
        await send(encode_signed(recipient, MSG_ANNOUNCE, None, recipient.announce_payload()))

        for _ in range(20):
            if state["handoff"]:
                break
            # keep re-announcing R; Bitle hands off on a verified direct announce
            await send(encode_signed(recipient, MSG_ANNOUNCE, None, recipient.announce_payload()))
            await asyncio.sleep(1.0)

        await client.stop_notify(CHAR_UUID)

    print("-" * 60)
    if not state["handoff"]:
        print("RESULT: FAIL — no hand-off received (check board log for reason)")
        return 1
    # The handed-off payload is a re-encoded envelope; confirm our ciphertext.
    if ciphertext in state["handoff"]:
        print("RESULT: PASS — Bitle stored the deposit and handed the exact")
        print("        envelope back to the tagged recipient. Courier path verified.")
        return 0
    print("RESULT: PARTIAL — hand-off received but ciphertext did not match")
    print(f"        deposited={ciphertext.hex()[:24]}…")
    return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
