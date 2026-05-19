import numpy as np
from PIL import Image

with open('window.bin', 'rb') as f:
    data = f.read()

arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)

# === LAYER 1: 3 XOR keys theo kênh màu ===
# Trích xuất từ Row 1 (pixels 52-103), align theo vị trí tuyệt đối
R_key = [0] * 10
G_key = [0] * 6
B_key = [0] * 14
for i in range(max(10, 14)):
    p = 52 + i
    if i < 10: R_key[p % 10] = arr[p, 0]
    if i < 6:  G_key[p % 6]  = arr[p, 1]
    if i < 14: B_key[p % 14] = arr[p, 2]

# Giải mã layer 1: XOR từng kênh với key tương ứng
dec1 = bytearray()
for p in range(2496):
    dec1.append(arr[p, 0] ^ R_key[p % 10])
    dec1.append(arr[p, 1] ^ G_key[p % 6])
    dec1.append(arr[p, 2] ^ B_key[p % 14])

# === LAYER 2: XOR key chu kỳ 6 byte ===
# Suy ra từ PNG header đã biết
key2 = [0x00, 0xab, 0x21, 0x10, 0x02, 0x00]
final = bytes(dec1[i] ^ key2[i % 6] for i in range(len(dec1)))

# Lưu file PNG
with open('decoded.png', 'wb') as f:
    f.write(final)

# Lật ảnh để đọc flag
img = Image.open('decoded.png')
img.transpose(Image.FLIP_LEFT_RIGHT).save('flag.png')