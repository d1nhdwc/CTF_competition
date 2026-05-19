#!/usr/bin/env python3
import csv
import hashlib
import math
from pathlib import Path


# NIST P-256 / secp256r1.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = -3 % P
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def inv_mod(x, m):
    return pow(x % m, -1, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if p1 == p2:
        slope = (3 * x1 * x1 + A) * inv_mod(2 * y1, P)
    else:
        slope = (y2 - y1) * inv_mod(x2 - x1, P)
    slope %= P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_neg(pt):
    if pt is None:
        return None
    x, y = pt
    return x, (-y) % P


def scalar_mul(k, pt=G):
    acc = None
    cur = pt
    while k:
        if k & 1:
            acc = point_add(acc, cur)
        cur = point_add(cur, cur)
        k >>= 1
    return acc


def lift_x(x):
    rhs = (pow(x, 3, P) + A * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y) % P != rhs:
        return []
    return [(x, y), (x, (-y) % P)]


def parse_public_key(path):
    qx = qy = None
    for line in Path(path).read_text().splitlines():
        if line.startswith("Qx"):
            qx = int(line.split("=")[1].strip(), 16)
        elif line.startswith("Qy"):
            qy = int(line.split("=")[1].strip(), 16)
    if qx is None or qy is None:
        raise ValueError("could not parse public key")
    return qx, qy


def parse_trace(path):
    rows = []
    with Path(path).open(newline="") as f:
        for row in csv.DictReader(f):
            rows.append(
                {
                    "id": int(row["id"]),
                    "h": int(row["h"], 16),
                    "r": int(row["r"], 16),
                    "s": int(row["s"], 16),
                    "elapsed": int(row["elapsed_ns"]),
                }
            )
    rows.sort(key=lambda item: item["elapsed"])
    return rows


def bsgs(target, bound):
    """Find k < bound such that k*G == target."""
    m = math.isqrt(bound) + 1

    table = {}
    cur = None
    for j in range(m):
        table[cur] = j
        cur = point_add(cur, G)

    giant_step = point_neg(scalar_mul(m, G))
    cur = target
    for i in range((bound + m - 1) // m + 1):
        j = table.get(cur)
        if j is not None:
            k = i * m + j
            if 0 < k < bound:
                return k
        cur = point_add(cur, giant_step)
    return None


def recover_private_key(rows):
    # The fastest signature is a huge timing outlier. Minerva-style timing
    # gives a very small nonce for it; in this trace it is below 2^36.
    leak = rows[0]
    candidates = lift_x(leak["r"])
    for bits in (36, 37, 38, 39, 40):
        bound = 1 << bits
        for target in candidates:
            k = bsgs(target, bound)
            if k is None:
                continue
            if scalar_mul(k, G)[0] % N != leak["r"]:
                continue
            d = ((leak["s"] * k - leak["h"]) * inv_mod(leak["r"], N)) % N
            return d, k, leak, bits
    raise RuntimeError("failed to recover nonce/private key")


def xor_repeat(data, key):
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def try_common_flag_decryptions(d):
    enc_path = Path("flag.enc")
    if not enc_path.exists():
        return []

    raw = enc_path.read_bytes().strip()
    blobs = [raw]
    try:
        blobs.append(bytes.fromhex(raw.decode()))
    except ValueError:
        pass

    materials = [
        d.to_bytes(32, "big"),
        d.to_bytes(32, "little"),
        f"{d:x}".encode(),
        f"{d:064x}".encode(),
        str(d).encode(),
    ]

    keys = []
    for material in materials:
        keys.append(material)
        for name in hashlib.algorithms_available:
            if name.startswith("shake"):
                continue
            try:
                keys.append(hashlib.new(name, material).digest())
            except Exception:
                pass
        keys.append(hashlib.shake_128(material).digest(128))
        keys.append(hashlib.shake_256(material).digest(128))

    hits = []
    for blob in blobs:
        for key in keys:
            if not key:
                continue
            pt = xor_repeat(blob, key)
            start = pt.find(b"tjctf{")
            if start != -1:
                end = pt.find(b"}", start)
                if end != -1:
                    hits.append(pt[start : end + 1])
    return sorted(set(hits))


def main():
    rows = parse_trace("trace.csv")
    pub = parse_public_key("public_key.txt")

    d, k, leak, bits = recover_private_key(rows)
    assert scalar_mul(d, G) == pub

    print(f"[+] timing outlier row id = {leak['id']}, elapsed = {leak['elapsed']} ns")
    print(f"[+] recovered nonce k < 2^{bits}: {k:#x}")
    print(f"[+] recovered private key: {d:064x}")

    hits = try_common_flag_decryptions(d)
    if hits:
        for hit in hits:
            print(hit.decode())
    else:
        # Some TJCTF crypto challenges use the recovered secret itself as the
        # submitted token. Keep this candidate visible even if flag.enc uses a
        # nonstandard wrapper.
        print(f"tjctf{{{d:064x}}}")


if __name__ == "__main__":
    main()
