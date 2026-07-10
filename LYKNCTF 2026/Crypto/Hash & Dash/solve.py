#!/usr/bin/env python3
import socket
import json
import re
import struct
import sys

HOST = "51.79.140.18"
PORT = 11643

MAX_KEY_LEN = 128

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def sha256_padding(total_len):
    return (
        b"\x80"
        + b"\x00" * ((56 - (total_len + 1) % 64) % 64)
        + struct.pack(">Q", total_len * 8)
    )

def compress_sha256(chunk, h):
    assert len(chunk) == 64

    w = list(struct.unpack(">16I", chunk)) + [0] * 48

    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (hh + S1 + ch + K[i] + w[i]) & 0xffffffff

        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xffffffff

        hh = g
        g = f
        f = e
        e = (d + t1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xffffffff

    return [
        (h[0] + a) & 0xffffffff,
        (h[1] + b) & 0xffffffff,
        (h[2] + c) & 0xffffffff,
        (h[3] + d) & 0xffffffff,
        (h[4] + e) & 0xffffffff,
        (h[5] + f) & 0xffffffff,
        (h[6] + g) & 0xffffffff,
        (h[7] + hh) & 0xffffffff,
    ]

def sha256_continue(extra, old_tag_hex, processed_len_before_extra):
    h = list(struct.unpack(">8I", bytes.fromhex(old_tag_hex)))

    final_data = extra + sha256_padding(processed_len_before_extra + len(extra))

    assert len(final_data) % 64 == 0

    for i in range(0, len(final_data), 64):
        h = compress_sha256(final_data[i:i + 64], h)

    return b"".join(struct.pack(">I", x) for x in h).hex()

def forge(original_msg, old_tag, append, key_len):
    glue = sha256_padding(key_len + len(original_msg))

    forged_msg = original_msg + glue + append

    processed_len = key_len + len(original_msg) + len(glue)

    forged_tag = sha256_continue(
        append,
        old_tag,
        processed_len
    )

    return forged_msg, forged_tag

def recv_until(sock, marker=b"> "):
    sock.settimeout(5)
    data = b""

    while marker not in data:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break

        if not chunk:
            break

        data += chunk

    return data

def recv_response(sock):
    sock.settimeout(5)
    data = b""

    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break

        if not chunk:
            break

        data += chunk

        if b"\n" in data:
            break

    return data

def parse_json_blob(data):
    if isinstance(data, bytes):
        data = data.decode(errors="replace")

    m = re.search(r"\{.*\}", data, re.S)
    if not m:
        return None

    try:
        return json.loads(m.group(0))
    except Exception:
        return None

def try_forge(key_len, append):
    s = socket.create_connection((HOST, PORT), timeout=5)

    banner = recv_until(s)
    info = parse_json_blob(banner)

    if not info:
        print("[!] Could not parse banner:")
        print(banner.decode(errors="replace"))
        s.close()
        return None, "", None

    original_msg = bytes.fromhex(info["message_hex"])
    old_tag = info["token"]

    forged_msg, forged_tag = forge(
        original_msg,
        old_tag,
        append,
        key_len
    )

    payload = {
        "msg": forged_msg.hex(),
        "tag": forged_tag,
    }

    s.sendall(json.dumps(payload).encode() + b"\n")

    out = recv_response(s)
    txt = out.decode(errors="replace")

    resp = parse_json_blob(txt)

    s.close()

    return resp, txt, payload

def is_real_success(resp, txt):
    low = txt.lower()

    if "flag" in low or "ctf{" in low:
        return True

    if isinstance(resp, dict):
        if resp.get("admin") is True:
            return True

    return False

def main():
    print("[*] Phase 1: finding SHA-256 secret length...")

    found_key_len = None

    for key_len in range(1, MAX_KEY_LEN + 1):
        append = b"&role=admin"

        resp, txt, payload = try_forge(key_len, append)

        print(f"[+] trying key_len={key_len}")
        print(txt.strip())

        if is_real_success(resp, txt):
            print("[+] REAL SUCCESS")
            print(json.dumps(payload))
            return

        if isinstance(resp, dict) and resp.get("ok") is True:
            found_key_len = key_len
            print(f"[+] valid token found, key_len = {key_len}")
            print("[*] Token forgery works. Now trying admin parser bypasses...")
            break

    if found_key_len is None:
        print("[!] Could not find valid key length.")
        return

    candidates = [
        b"&role=admin",
        b"&admin=true",
        b"&admin=True",
        b"&admin=1",
        b"&is_admin=true",
        b"&is_admin=True",
        b"&is_admin=1",
        b"&isAdmin=true",
        b"&isAdmin=True",
        b"&isAdmin=1",
        b"&user=admin",
        b"&username=admin",
        b"&name=admin",
        b"&uid=0",
        b"&id=0",
        b"&access=admin",
        b"&permission=admin",
        b"&permissions=admin",
        b"&scope=admin",
        b"&grant=admin",
        b"&group=admin",
        b"&groups=admin",
        b"&role=administrator",
        b"&role=root",
        b"&admin=yes",
        b"&admin=on",
        b"&superuser=true",
        b"&superuser=1",

        b"&role=admin&admin=true",
        b"&admin=true&role=admin",
        b"&user=admin&role=admin",
        b"&role=admin&user=admin",
        b"&admin=1&role=admin",
        b"&role=admin&admin=1",
        b"&uid=0&role=admin",
        b"&role=admin&uid=0",

        b";role=admin",
        b";admin=true",
        b";admin=1",

        b"\nrole=admin",
        b"\nadmin=true",
        b"\nadmin=1",
    ]

    print(f"[*] Phase 2: trying {len(candidates)} admin payload candidates...")

    for append in candidates:
        resp, txt, payload = try_forge(found_key_len, append)

        print(f"[+] trying append={append!r}")
        print(txt.strip())

        if is_real_success(resp, txt):
            print("[+] REAL SUCCESS")
            print(json.dumps(payload))
            return

    print("[!] No admin:true with current candidates.")
    print("[!] Crypto part is solved: key_len =", found_key_len)
    print("[!] Add more parser candidates if needed.")

if __name__ == "__main__":
    main()