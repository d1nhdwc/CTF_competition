#!/usr/bin/env python3
import socket
import json
import re
import ast

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "51.79.140.18"
PORT = 12926

KDF_INFO = b"lyknctf-2026"

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

def parse_instance(text):
    print("[*] Raw server output:")
    print(text)

    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("No JSON object found in server output")

    blob = m.group(0)

    try:
        return json.loads(blob)
    except Exception:
        return ast.literal_eval(blob)

def derive_key(s_alg, salt, N, Q):
    ikm = (
        s_alg.to_bytes(2, "big")
        + N.to_bytes(2, "big")
        + Q.to_bytes(2, "big")
    )

    return HKDF(
        master=ikm,
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=KDF_INFO,
    )

def main():
    text = recv_all(HOST, PORT)
    inst = parse_instance(text)

    params = inst["parameters"]
    enc = inst["encrypted_flag"]

    N = int(params["N"])
    Q = int(params["q"])
    Q_PRIME = int(params["q_prime"])

    salt = bytes.fromhex(enc["salt"])
    nonce = bytes.fromhex(enc["nonce"])
    ciphertext = bytes.fromhex(enc["ciphertext"])
    tag = bytes.fromhex(enc["tag"])

    ct_and_tag = ciphertext + tag

    print(f"[*] N={N}, Q={Q}, Q_PRIME={Q_PRIME}")
    print(f"[*] Bruting s_alg = 0..{Q_PRIME - 1}")

    for s_alg in range(Q_PRIME):
        key = derive_key(s_alg, salt, N, Q)
        aesgcm = AESGCM(key)

        try:
            pt = aesgcm.decrypt(nonce, ct_and_tag, None)
        except Exception:
            continue

        print("\n[+] FOUND")
        print("[+] s_alg =", s_alg)
        print("[+] plaintext bytes =", pt)

        try:
            decoded = pt.decode()
            print("[+] plaintext =", decoded)
        except Exception:
            decoded = pt.decode(errors="replace")
            print("[+] plaintext decoded =", decoded)

        m = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", pt)
        if m:
            print("[+] FLAG =", m.group(0).decode(errors="replace"))

        return

    print("[-] No valid key found")

if __name__ == "__main__":
    main()
