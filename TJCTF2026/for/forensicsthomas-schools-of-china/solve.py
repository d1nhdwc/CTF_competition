from PIL import Image
import re

data = open("chall.tsc", "rb").read()

w, h = 60, 61
off = 0x11
raw = data[off:]

pixels = []
for i in range(0, len(raw), 4):
    r, g, b, a = raw[i:i+4]
    pixels.append((r, g, b))

chunks = []

for y in range(h):
    for x in range(w):
        r, g, b = pixels[y * w + x]
        if all(32 <= c < 127 for c in (r, g, b)):
            s = chr(r) + chr(g) + chr(b)
            if not (r == g == b):
                chunks.append((x, y, s))

chunks.sort(key=lambda t: (t[1], t[0]))

msg = ""
started = False

for x, y, s in chunks:
    if s == "tjc":
        started = True

    if started:
        msg += s

flag = re.search(r"tjctf\{[^}]+\}", msg).group(0)
print(flag)