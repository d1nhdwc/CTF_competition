from PIL import Image

data = open("chall.tsc", "rb").read()

w, h = 60, 61
off = 0x11

raw = data[off:]

# bỏ alpha, chỉ lấy RGB
rgb = b""
for i in range(0, len(raw), 4):
    r, g, b, a = raw[i:i+4]
    rgb += bytes([r, g, b])

img = Image.frombytes("RGB", (w, h), rgb)

# phóng to để nhìn rõ
img = img.resize((w * 10, h * 10), Image.NEAREST)
img.save("render.png")