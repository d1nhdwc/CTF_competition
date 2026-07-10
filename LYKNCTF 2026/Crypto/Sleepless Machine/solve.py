#!/usr/bin/env python3
import socket
import json
import re
import sys
import os
import multiprocessing as mp

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

HOST = "51.79.140.18"
PORT = 15320

KDF_INFO = b"lyknctf-2026"

G_N = None
G_Q = None
G_QP = None
G_NONCE = None
G_CT = None
G_TAG = None

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

def parse_json_from_text(text):
    dec = json.JSONDecoder()

    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, end = dec.raw_decode(text[i:])
            return obj
        except Exception:
            pass

    m = re.search(r"\{.*\}", text, re.S)
    if m:
        return json.loads(m.group(0))

    raise ValueError("No JSON object found")

def derive_key(s_alg, N, q, q_prime):
    ikm = (
        s_alg.to_bytes(4, "big")
        + N.to_bytes(2, "big")
        + q.to_bytes(2, "big")
        + q_prime.to_bytes(4, "big")
    )

    return HKDF(
        master=ikm,
        key_len=32,
        salt=str(N).encode(),
        hashmod=SHA256,
        context=KDF_INFO,
    )

def init_worker(N, q, q_prime, nonce, ct, tag):
    global G_N, G_Q, G_QP, G_NONCE, G_CT, G_TAG
    G_N = N
    G_Q = q
    G_QP = q_prime
    G_NONCE = nonce
    G_CT = ct
    G_TAG = tag

def try_range(task):
    start, end = task

    for s_alg in range(start, end):
        key = derive_key(s_alg, G_N, G_Q, G_QP)

        cipher = AES.new(key, AES.MODE_GCM, nonce=G_NONCE)

        try:
            pt = cipher.decrypt_and_verify(G_CT, G_TAG)
        except Exception:
            continue

        return s_alg, pt

    return None

def solve_instance(inst, workers=None):
    params = inst["parameters"]
    enc = inst["encrypted_flag"]

    N = int(params["N"])
    q = int(params["q"])
    q_prime = int(params["q_prime"])

    nonce = bytes.fromhex(enc["nonce"])
    ct = bytes.fromhex(enc["ciphertext"])
    tag = bytes.fromhex(enc["tag"])

    print("[*] N       =", N)
    print("[*] q       =", q)
    print("[*] q_prime =", q_prime)
    print("[*] nonce   =", nonce.hex())
    print("[*] ct len  =", len(ct))
    print(f"[*] brute s_alg = 0..{q_prime - 1}")

    if workers is None:
        workers = max(1, min(os.cpu_count() or 1, 8))

    print("[*] workers =", workers)

    chunk_size = 2000
    tasks = [
        (i, min(i + chunk_size, q_prime))
        for i in range(0, q_prime, chunk_size)
    ]

    with mp.Pool(
        processes=workers,
        initializer=init_worker,
        initargs=(N, q, q_prime, nonce, ct, tag),
    ) as pool:
        done = 0

        for res in pool.imap_unordered(try_range, tasks):
            done += chunk_size

            if done % 100000 == 0:
                print(f"[*] tried about {min(done, q_prime)}/{q_prime}")

            if res is None:
                continue

            s_alg, pt = res

            print("\n[+] FOUND")
            print("[+] s_alg =", s_alg)
            print("[+] plaintext bytes =", pt)

            try:
                print("[+] plaintext =", pt.decode())
            except Exception:
                print("[+] plaintext hex =", pt.hex())

            m = re.search(rb"LYKN(?:CTF)?\{[^}]+\}", pt)
            if m:
                print("[+] FLAG =", m.group(0).decode(errors="replace"))

            pool.terminate()
            return

    print("[-] No valid s_alg found")

def main():
    if len(sys.argv) >= 2 and sys.argv[1].endswith(".json"):
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            text = f.read()
    else:
        host = sys.argv[1] if len(sys.argv) >= 2 else HOST
        port = int(sys.argv[2]) if len(sys.argv) >= 3 else PORT

        print(f"[*] connecting to {host}:{port}")
        text = recv_all(host, port)

    print("[*] raw output:")
    print(text)

    inst = parse_json_from_text(text)
    solve_instance(inst)

if __name__ == "__main__":
    main()
