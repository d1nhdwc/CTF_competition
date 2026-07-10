#!/usr/bin/env python3
import sys
import re
import json
import requests

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import unpad

def derive_key(V, N, q, salt_str):
    ikm = (
        V.to_bytes(4, "big")
        + N.to_bytes(2, "big")
        + q.to_bytes(2, "big")
        + salt_str.encode("utf-8")
    )

    return HKDF(
        master=ikm,
        key_len=32,
        salt=str(N).encode("utf-8"),
        hashmod=SHA256,
    )

def load_json(target, endpoint):
    target = target.rstrip("/")

    if target.startswith("http://") or target.startswith("https://"):
        r = requests.get(target + endpoint, timeout=10)
        r.raise_for_status()
        return r.json()

    with open(target, "r", encoding="utf-8") as f:
        return json.load(f)

def possible_sum_from_mod(residue, count, mod=127):
    """
    Sum of count ternary coefficients lies in [-count, count].
    We know sum % 127 = residue.
    Return all possible integer sums.
    """
    out = []
    for s in range(-count, count + 1):
        if s % mod == residue:
            out.append(s)
    return out

def decrypt_with_V(pub, V):
    params = pub["parameters"]
    enc = pub["encrypted_flag"]

    N = int(params["N"])
    q = int(params["q"])

    iv = bytes.fromhex(enc["iv"])
    ct = bytes.fromhex(enc["ciphertext"])
    salt_str = enc["salt"]

    key = derive_key(V, N, q, salt_str)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return unpad(cipher.decrypt(ct), AES.block_size)

def looks_like_flag(pt):
    return re.search(rb"LYKN(?:CTF)?\{[ -~]{1,200}\}", pt) is not None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} http://INSTANCE:PORT")
        return

    target = sys.argv[1].rstrip("/")

    pub = load_json(target, "/public.json")
    side = load_json(target, "/side_channel.json")

    params = pub["parameters"]
    N = int(params["N"])
    q_prime = int(params["q_prime"])

    cons = side["constraints"]

    # N=127 => even indices: 64, odd indices: 63
    f_even = possible_sum_from_mod(cons["f_even_sum_mod_127"], 64)
    f_odd  = possible_sum_from_mod(cons["f_odd_sum_mod_127"], 63)
    g_even = possible_sum_from_mod(cons["g_even_sum_mod_127"], 64)
    g_odd  = possible_sum_from_mod(cons["g_odd_sum_mod_127"], 63)

    print("[*] f_even candidates =", f_even)
    print("[*] f_odd  candidates =", f_odd)
    print("[*] g_even candidates =", g_even)
    print("[*] g_odd  candidates =", g_odd)

    V_candidates = set()

    for fe in f_even:
        for fo in f_odd:
            sf = fe + fo
            for ge in g_even:
                for go in g_odd:
                    sg = ge + go
                    V_candidates.add((sf * sg) % q_prime)

    V_candidates = sorted(V_candidates)

    print("[*] V candidates from side-channel =", V_candidates)

    # Try side-channel candidates first.
    for V in V_candidates:
        try:
            pt = decrypt_with_V(pub, V)
        except Exception:
            continue

        print(f"[+] padding-valid V={V}, pt={pt!r}")

        if looks_like_flag(pt):
            print("[+] REAL FLAG:", re.search(rb"LYKN(?:CTF)?\{[ -~]{1,200}\}", pt).group(0).decode())
            return

    print("[!] Side-channel candidates did not give flag. Falling back to full brute...")

    padding_valid = []

    for V in range(q_prime):
        try:
            pt = decrypt_with_V(pub, V)
        except Exception:
            continue

        padding_valid.append((V, pt))

        if looks_like_flag(pt):
            print("[+] REAL FLAG:", re.search(rb"LYKN(?:CTF)?\{[ -~]{1,200}\}", pt).group(0).decode())
            print("[+] V =", V)
            return

    print("[!] No flag-looking plaintext found.")
    print("[*] All padding-valid candidates:")
    for V, pt in padding_valid:
        print(f"V={V}: {pt!r}")

if __name__ == "__main__":
    main()
