import unicodedata

s = """Ỉ H̰OP̀É ÎM̊ OKAỸ ḂÜT̄ Ỉ ŇËẼD̄ H̃ȨL̂ṔṔP̌"""

inner = ""
for i in range(0x10, 0x500):
    for ch in s:
        if unicodedata.combining(ch):
            inner += chr(ord(ch) - 0x300)
    print(f"tjctf{{{inner}}}")