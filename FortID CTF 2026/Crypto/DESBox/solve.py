#!/usr/bin/env python3
from pwn import *

HOST = "desbox-a95a4876652d.inst4.ctf.fortid.com"
PORT = 1337

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl = True, sni = HOST)
    return process(["python3", "DESBox.py"])

p = conn()

K0 = b'\x00' * 24
K1 = b'\x02' * 24

def keyb(key_a, key_b, ct):
    p.sendlineafter(b"C:\\> ", b"KEYB")

    p.sendlineafter(b"KEY A> ", key_a.hex().encode())
    p.sendlineafter(b"KEY B> ", key_b.hex().encode())

    p.recvuntil(b"C:\\FLAG.BIN encrypted under Key A:\n")
    flag_ct = bytes.fromhex(p.recvline().strip().decode())

    p.sendlineafter(b"Debug ciphertext> ", ct.hex().encode())

    p.recvuntil(b"Debug output:\n")
    plaintext = bytes.fromhex(p.recvline().strip().decode())

    return flag_ct, plaintext


# Stage 1: Encrypt FLAG using K0
flag_ct, _ = keyb(K0, K1, b'\x00'*8)

log.success(f"Encrypted FLAG: {flag_ct.hex()}")

# Stage 2: Decrypt using the exact same effective key K0
_, flag = keyb(K1, K0, flag_ct)

log.success(f"FLAG: {flag!r}")

p.interactive()
