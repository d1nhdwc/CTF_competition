#!/usr/bin/env python3
import socket
import json
import re
import sys
import math
import hashlib
from math import gcd

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST = "51.79.140.18"
PORT = 15266

def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def lcm(a, b):
    return a // gcd(a, b) * b

def recv_all(host, port):
    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(3)

    data = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break

    s.close()
    return data.decode(errors="replace")

def load_params(arg=None):
    if arg and not arg.startswith("nc:"):
        with open(arg, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = recv_all(HOST, PORT)

    print("[*] raw output:")
    print(text)

    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("No JSON object found")

    return json.loads(m.group(0))

def continued_fraction(n, d):
    while d:
        a = n // d
        yield a
        n, d = d, n - a * d

def convergents_from_cf(cf):
    n0, n1 = 1, 0
    d0, d1 = 0, 1

    for a in cf:
        n2 = a * n0 + n1
        d2 = a * d0 + d1

        yield n2, d2

        n1, n0 = n0, n2
        d1, d0 = d0, d2

def recover_rsa_wiener(N, e):
    """
    e*d - k*phi = 1.
    For small d, k/d is a convergent of e/N.
    """
    for k, d in convergents_from_cf(continued_fraction(e, N)):
        if k == 0:
            continue

        ed_minus_1 = e * d - 1

        if ed_minus_1 % k != 0:
            continue

        phi = ed_minus_1 // k

        # phi = N - (p+q) + 1
        s = N - phi + 1
        discr = s * s - 4 * N

        if discr < 0:
            continue

        root = math.isqrt(discr)
        if root * root != discr:
            continue

        if (s + root) % 2 != 0:
            continue

        p = (s + root) // 2
        q = (s - root) // 2

        if p * q == N:
            return d, p, q, phi, k

    raise RuntimeError("Wiener failed")

def derive_aes_key(d, S, lambda_n, salt=b"FastLane-RSA-2024"):
    d_bytes = long_to_bytes(d)
    V_int = d_bytes[:16]

    H1 = hashlib.sha256(V_int).digest()
    H2 = hashlib.sha256(long_to_bytes(S)).digest()
    H3 = hashlib.sha256(long_to_bytes(lambda_n)).digest()

    IKM = H1 + H2 + H3

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"FastLane-AES-Key",
    )

    return hkdf.derive(IKM)

def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    params = load_params(arg)

    N = int(params["N"])
    e = int(params["e"])

    ct = bytes.fromhex(params["encrypted_flag"])
    nonce = bytes.fromhex(params["nonce"])
    tag = bytes.fromhex(params["tag"])

    print("[*] N bits =", N.bit_length())
    print("[*] e bits =", e.bit_length())
    print("[*] running Wiener attack...")

    d, p, q, phi, k = recover_rsa_wiener(N, e)

    if p > q:
        p, q = q, p

    lambda_n = lcm(p - 1, q - 1)

    # S có leak sẵn; cũng có thể tính lại từ p+q.
    if "leakage2" in params and "S" in params["leakage2"]:
        S = int(params["leakage2"]["S"])
    else:
        small_value = 2**20 * 3 * 5 * 7
        S = gcd(p + q, small_value)

    print("[+] d =", d)
    print("[+] d bits =", d.bit_length())
    print("[+] p bits =", p.bit_length())
    print("[+] q bits =", q.bit_length())
    print("[+] S =", S)
    print("[+] lambda_n =", lambda_n)

    key = derive_aes_key(d, S, lambda_n)

    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct + tag, None)

    print("\n[+] plaintext bytes =", pt)

    try:
        print("[+] plaintext =", pt.decode())
    except Exception:
        print("[+] plaintext hex =", pt.hex())

    m = re.search(rb"LYKN(?:CTF)?\{[^}]+\}", pt)
    if m:
        print("[+] FLAG =", m.group(0).decode(errors="replace"))

if __name__ == "__main__":
    main()
