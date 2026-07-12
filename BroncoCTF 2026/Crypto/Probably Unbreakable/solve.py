#!/usr/bin/env python3
from pwn import *
import re
import string

HOST = args.HOST or "broncoctf-probably.chals.io"
PORT = int(args.PORT or 443)
COUNT = int(args.COUNT or 2000)

KEYSPACE = (string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits + "_-").encode()

context.log_level = args.LOG_LEVEL or "info"

io = remote(
    HOST,
    PORT,
    ssl=True,
    sni=HOST,
)
io.sendlineafter(
    b"How many list-scrambles do you want?",
    b"0"
)
io.sendlineafter(
    b"How many random-letter-pickings do you want?",
    b"0"
)
io.sendlineafter(
    b"How many flag encryptions do you want?",
    str(COUNT).encode()
)

ciphertexts = []

while len(ciphertexts) < COUNT:
    line = io.recvline(timeout=20)
    if not line:
        break

    line = line.strip()
    if re.fullmatch(rb"[0-9a-fA-F]+", line) and len(line) % 2 == 0:
        ciphertexts.append(bytes.fromhex(line.decode()))

io.close()

if not ciphertexts:
    raise SystemExit("[-] Không lấy được ciphertext nào từ server")

lengths = {len(ct) for ct in ciphertexts}
if len(lengths) != 1:
    raise SystemExit(f"[-] Ciphertext có độ dài không đồng nhất: {lengths}")

flag_len = lengths.pop()
log.info(f"Collected {len(ciphertexts)} encryptions")
log.info(f"Flag length: {flag_len}")

recovered = bytearray()
ambiguous = {}

for pos in range(flag_len):
    # Với y = flag_byte XOR key_byte và key_byte thuộc KEYSPACE:
    # flag_byte phải nằm trong {y XOR k | k thuộc KEYSPACE}.
    candidates = set(range(256))

    for ct in ciphertexts:
        candidates &= {ct[pos] ^ k for k in KEYSPACE}

    if len(candidates) == 1:
        recovered.append(next(iter(candidates)))
    else:
        ambiguous[pos] = sorted(candidates)

        printable = [x for x in candidates if 32 <= x <= 126]
        recovered.append(printable[0] if len(printable) == 1 else ord("?"))

print(f"[+] Partial: {recovered.decode(errors='replace')}")

if ambiguous:
    print("[-] Một số vị trí vẫn còn mơ hồ:")
    for pos, candidates in ambiguous.items():
        shown = [
            chr(x) if 32 <= x <= 126 else f"\\x{x:02x}"
            for x in candidates
        ]
        print(f"    pos {pos}: {shown}")

    print("[*] Chạy lại với nhiều mẫu hơn, ví dụ:")
    print(f"    python3 {__file__} COUNT=2000")
else:
    print(f"[+] FLAG: {recovered.decode()}")