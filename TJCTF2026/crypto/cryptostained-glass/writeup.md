# TJCTF 2026 — Stained Glass (Crypto)

**Flag:** `tjctf{three_keys_one_window}`

## Tổng quan

| Thông tin | Chi tiết |
|-----------|----------|
| CTF | TJCTF 2026 |
| Thể loại | Crypto |
| Tên challenge | Stained Glass |
| File đề bài | `window.bin` (7488 bytes) |

## Phân tích ban đầu

File `window.bin` có kích thước **7488 bytes**. Vì tên challenge là "stained glass" (kính màu) và file tên "window" (cửa sổ), ta thử xem dữ liệu dưới dạng ảnh RGB:

- 7488 ÷ 3 = **2496 pixel RGB**
- Phân tích thừa số: 2496 = 48 × 52

Khi render dưới dạng ảnh 52×48, ta thấy toàn bộ là nhiễu màu (noise) — không có hình ảnh rõ ràng.

### Quan sát quan trọng

- Entropy rất cao (~7.95 bit/byte) → dữ liệu trông như ngẫu nhiên
- **Tất cả 2496 pixel đều có màu khác nhau** → dữ liệu được tạo có chủ đích
- Mỗi kênh R, G, B đều sử dụng gần đủ 256 giá trị

## Phát hiện Key Row

Khi reshape thành 52×48 và kiểm tra tính tuần hoàn (periodicity) theo hàng, ta phát hiện:

| Hàng | R period | G period | B period |
|------|----------|----------|----------|
| Row 1 | **10** | **6** | **14** |
| Row 46 | **10** | **6** | **14** |
| Tất cả hàng khác | 52 (không tuần hoàn) | 52 | 52 |

**Chỉ có Row 1 và Row 46 có kênh màu tuần hoàn với chu kỳ ngắn!**

Các chu kỳ 10, 6, 14 liên quan đến phân tích thừa số:
- 10 = 2 × 5
- 6 = 2 × 3
- 14 = 2 × 7

→ Gợi ý rằng dữ liệu được mã hóa bằng 3 XOR key khác nhau cho 3 kênh màu.

## Layer 1: Ba XOR Key theo kênh màu

### Trích xuất key

Row 1 bắt đầu từ pixel 52 (vì mỗi hàng rộng 52 pixel). Các giá trị R, G, B tại row 1 lặp lại đều đặn, cho phép trích xuất 3 key:

**Lưu ý quan trọng:** Key phải được **align theo vị trí tuyệt đối** (`p % period`), không phải vị trí tương đối trong hàng!

Ví dụ: pixel 52 có `52 % 10 = 2`, nên `R_key[2] = R[pixel_52]`.

```python
# Key đã align đúng theo vị trí tuyệt đối p
R_key = [0xbe, 0x2e, 0x1e, 0xe8, 0x90, 0xae, 0x3e, 0x0e, 0xf8, 0x80]  # period 10
G_key = [0x5e, 0x6e, 0x67, 0xf1, 0x89, 0xcf]                          # period 6
B_key = [0xeb, 0x08, 0x23, 0x9f, 0x98, 0x0f, 0x17, 0xca,              # period 14
         0x29, 0x02, 0xbe, 0xb9, 0x2e, 0x36]
```

### Giải mã layer 1

```python
for p in range(2496):
    R_dec[p] = R[p] ^ R_key[p % 10]
    G_dec[p] = G[p] ^ G_key[p % 6]
    B_dec[p] = B[p] ^ B_key[p % 14]
```

**Kiểm chứng:** Toàn bộ Row 1 (pixel 52–103) sau khi giải mã đều bằng **0x00** cho cả 3 kênh → Key đúng!

### Phân tích sau layer 1

Sau khi bóc layer 1:

| Hàng | Giá trị giải mã |
|------|-----------------|
| Row 1 | Toàn bộ = `0x00` (key row) |
| Row 46 | Lặp lại chu kỳ 2: R=`{0xab, 0x12}`, G=`{0x8a, 0x02}`, B=`{0x31, 0x00}` |
| Row 47 | Tương tự Row 46 (trừ vài byte cuối) |
| Các hàng khác | Dữ liệu entropy cao |

## Layer 2: XOR Key chu kỳ 6 byte

### Đoán file format

Byte đầu tiên sau giải mã layer 1 là **0x89** — trùng với magic byte của **PNG**!

Header PNG chuẩn: `89 50 4E 47 0D 0A 1A 0A`

So sánh với kết quả giải mã layer 1:

```
Layer 1 output:  89 fb 6f 57 0f 0a 1a a1
PNG header:      89 50 4e 47 0d 0a 1a 0a
XOR cần thiết:   00 ab 21 10 02 00 00 ab ...
```

Key XOR cần thiết: `[0x00, 0xab, 0x21, 0x10, 0x02, 0x00]` — **chu kỳ 6 byte!**

### Kiểm chứng

Áp dụng key layer 2 lên toàn bộ byte stream:

```python
key2 = [0x00, 0xab, 0x21, 0x10, 0x02, 0x00]

for i in range(7488):
    final[i] = dec1[i] ^ key2[i % 6]
```

Kết quả: **File PNG hợp lệ!**

```
89 50 4e 47 0d 0a 1a 0a  →  ✅ PNG magic header
00 00 00 0d 49 48 44 52  →  ✅ IHDR chunk (13 bytes)
00 00 02 58 00 00 00 8c  →  Width=600, Height=140
08 02                    →  8-bit RGB
```

## Kết quả

File PNG giải mã có kích thước **600×140 pixel**, chứa text bị lật ngang (mirror). Sau khi lật lại:

```
tjctf{three_keys_one_window}
```

## Script giải hoàn chỉnh

```python
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
```

## Tóm tắt

Challenge mã hóa một file PNG bằng **2 layer XOR**:

1. **Layer 1** — "Three keys": Ba XOR key độc lập cho 3 kênh R, G, B với chu kỳ lần lượt là 10, 6, 14. Key được giấu trong **Row 1** của ảnh 52×48 (row có tính tuần hoàn đặc biệt).

2. **Layer 2** — "One window": Một XOR key chung chu kỳ 6 byte áp dụng lên toàn bộ byte stream. Key được suy ra bằng known-plaintext attack với PNG header.

Tên flag `three_keys_one_window` chính là mô tả cách mã hóa: **ba key (cho 3 kênh) + một cửa sổ (file PNG ẩn bên trong)**.
