#!/usr/bin/env python3
"""
Solver / model for "DIDDY LICENSE CHECKER" (v1t CTF).

Reverse-engineered pipeline (from disassembly of main + helpers):

  Q1  animal       -> must equal "duck"            (cmp dword == 0x6b637564)
  Q2  lucky number -> 32 chars, digit[i] == fib(i) % 9, digit[0]=='0'
                      => "01123584371808876415628101123584"
                      => hex_to_bytes(lucky)         == 16-byte AES-128 IV
  Q3  license name -> used two ways:
         (a) URL = "http://v1t.site/" + name   (http_get -> server returns KEY hex)
         (b) xor_bytes(arr[96], len=96, key=name) -> 96 ASCII-hex chars
             => hex_to_bytes(...)               == 48-byte CIPHERTEXT
      Server response -> hex_to_bytes(resp[:32]) == 16-byte AES-128 KEY

  plaintext = AES-128-CBC-decrypt(CIPHERTEXT, KEY, IV)
  require plaintext startswith "v1t"            (after the final hex decode)
  FLAG = bytes.fromhex(plaintext)               -> printed "Oh hi diddy here your flag: %s"

Note: xor_bytes uses arr as 96 little-endian dwords (only low byte matters)
      and the key is cycled modulo len(name).
"""
import sys
from Crypto.Cipher import AES  # pip install pycryptodome

# arr: 96 dwords from .data @0x4120 (low byte used)
ARR = [0x55,0x0f,0x02,0x01,0x59,0x15,0x51,0x19,0x50,0x0d,0x45,0x18,0x44,0x12,0x00,0x42,
       0x4b,0x55,0x57,0x05,0x54,0x54,0x52,0x56,0x50,0x1a,0x55,0x59,0x01,0x06,0x4e,0x5c,
       0x58,0x52,0x55,0x0d,0x17,0x52,0x1e,0x00,0x59,0x4b,0x14,0x42,0x45,0x06,0x47,0x4f,
       0x02,0x00,0x05,0x55,0x01,0x50,0x01,0x05,0x1b,0x50,0x5a,0x56,0x06,0x41,0x54,0x5b,
       0x50,0x01,0x5f,0x40,0x52,0x15,0x56,0x56,0x46,0x4b,0x14,0x45,0x55,0x16,0x1e,0x50,
       0x52,0x05,0x5d,0x00,0x51,0x01,0x07,0x1e,0x57,0x50,0x5d,0x00,0x1b,0x59,0x5e,0x53]

def fib_mod9(i):
    a, b = 1, 0
    for _ in range(i):
        a, b = a + b, a
    return b % 9   # matches the asm loop's returned value

def lucky_number():
    return "0" + "".join(str(fib_mod9(i)) for i in range(1, 32))  # 32 chars

def xor_hex(name):
    nb = name.encode()
    out = bytes((ARR[i] ^ nb[i % len(nb)]) & 0xff for i in range(len(ARR)))
    return out  # 96 bytes; must all be ASCII hex chars

def solve(name, server_key_hex):
    iv = bytes.fromhex(lucky_number())                 # 16 bytes
    xh = xor_hex(name)
    s = xh.decode("latin1")
    if any(c not in "0123456789abcdefABCDEF" for c in s):
        return None, f"name produces non-hex xor output: {s!r}"
    ct = bytes.fromhex(s)                               # 48 bytes
    key = bytes.fromhex(server_key_hex)[:16]            # 16 bytes
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    # strip PKCS#7-ish / trailing, then the binary re-hexdecodes the plaintext
    try:
        # plaintext is ASCII hex of the flag; trim at first non-hex
        txt = pt.decode("latin1")
        hexpart = ""
        for c in txt:
            if c in "0123456789abcdefABCDEF":
                hexpart += c
            else:
                break
        if len(hexpart) % 2: hexpart = hexpart[:-1]
        flag = bytes.fromhex(hexpart)
        return flag, None
    except Exception as e:
        return None, f"decode error: {e} (raw pt={pt!r})"

if __name__ == "__main__":
    print("lucky number :", lucky_number())
    print("IV (hex)     :", bytes.fromhex(lucky_number()).hex())
    if len(sys.argv) >= 3:
        name, key = sys.argv[1], sys.argv[2]
        flag, err = solve(name, key)
        print("flag:", flag if flag else f"(none) {err}")
    else:
        print("usage: solve.py <license_name> <server_key_hex>")
