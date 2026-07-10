# IDAPython helper for ducktricks.bin (V1T CTF "10X59")
#
# PROBLEM: you loaded the file as a raw "Binary file" (16-bit x86), so IDA shows only `db`.
# FIX: reload as Xtensa, OR just run this script which prints the encrypted blob + all
#      constants so you can paste them back to me, AND tries the decryption locally.
#
# HOW TO USE
# 1. In IDA: File > Script file... > select this file.
# 2. Read the Output window. It prints the recovered strings + ciphertext.
# 3. If you reloaded as Xtensa (recommended), also decompile sub at EA 0x42001a8c
#    (or file-offset 0x21a8c in the flat load) with F5 and paste the pseudocode to me.
#
# RELOAD-AS-XTENSA STEPS (best):
#   File > Open > ducktricks.bin  ->  Processor type: "Tensilica Xtensa (xtensa)" , little-endian
#   Create a segment for code:  load address 0x42000020 , file offset 0x20020 , size 0x22078
#   Create rodata segment:      load address 0x3c030020 , file offset 0x20     , size 0x11610
#   Then jump to 0x42001a8c , press C (code) , P (make function) , F5 (decompile).

import idaapi, idc

def get_bytes(off, n):
    # works whether loaded flat (off==EA) or needs translation; try linear address = off
    b = idaapi.get_bytes(off, n)
    return b if b else b""

# In the FLAT raw load, the rodata blob is at address 0x120.
BLOB_EA = 0x120
blob = get_bytes(BLOB_EA, 0x60)
if not blob:
    # maybe loaded with imagebase; try 0
    blob = bytes(idc.get_bytes(0x120, 0x60) or b"")

dec = bytes(c ^ 0x42 for c in blob)
print("[*] blob @0x120 XOR 0x42 ->")
print("   ", dec)

# isolate ciphertext (between 'v1.3\r\n' and the 0x00 terminator)
i = dec.find(b"v1.3\r\n")
if i >= 0:
    start = i + len(b"v1.3\r\n")
    end = dec.find(b"\x00", start)
    enc = blob[start:end]            # RAW ciphertext bytes (still XOR-0x42 encoded form)
    enc_dec = dec[start:end]         # after the global XOR 0x42
    print("[*] ciphertext (raw)      :", enc.hex(" "))
    print("[*] ciphertext (^0x42)    :", enc_dec.hex(" "))
    print("[*] length:", len(enc_dec))

print("\n[*] Now decompile the function at 0x42001a8c (F5) and paste here.")
print("[*] Key constants: MUL=0x6c62272e ADD=0x07354a6b SEED=0xdeadbeef")
print("[*] CRC poly=0x80000057 target=0x9456fdd0 ; password='VaultPass v1.3'")
