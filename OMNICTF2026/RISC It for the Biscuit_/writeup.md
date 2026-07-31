# RISCBiscReal Writeup

## Thông tin

- Challenge: `RISCBiscReal`
- Category: Binary Exploitation / Pwn
- Platform: Windows x86-64 host, guest RISC-V RV64IM
- Target file: `C:\chall\flag.txt`
- Flag lấy được:

```text
OmniCTF{4llIn_Du3_T1me!-ash9+ujdsmnA1}
```

## Tóm tắt

VM không có MMU và dùng guest address như host virtual address. Guest code được load vào heap của process host, còn toàn bộ load/store/fetch của RV64IM interpreter đều dereference trực tiếp host pointer. Vì vậy payload RISC-V có arbitrary read/write trong process Windows.

Exploit cuối:

1. Leak host pointer của guest code bằng `auipc`.
2. Từ đó suy ra VM context `ctx = guest_code - 0x110`.
3. Scan metadata quanh heap để tìm PE base của `RV64VMv4.exe` dưới ASLR.
4. Scan host stack để tìm đúng return slot của frame `execute(ctx)`.
5. Resolve `kernel32` từ IAT `CreateFileW`, rồi parse import của `kernel32` để tìm `ntdll` và `RtlExitUserProcess`.
6. Dựng fake VM context trong heap.
7. Overwrite saved registers/return address của native `execute()` để reuse code có sẵn ở `main+0x1c37`, đoạn này tự gọi `CreateFileW`, `ReadFile`, `CloseHandle`.
8. Sau khi flag được đọc vào heap, ROP chain gọi lại `execute(print_context)`.
9. `print_context` chạy syscall VM `100` để in buffer flag.
10. Exit sạch qua `RtlExitUserProcess(0)`.

## Recon

File chính:

```text
RV64VMv4.exe
RV64VMv4.pdb
prime/
flag.txt
```

Hash binary đã phân tích:

```text
RV64VMv4.exe  4a8a472ebdbbdb48bb1c54f08975785ae8756b4d10066e0676b9e92f61bce3bd
RV64VMv4.pdb  d4a200a0c2093f5ac514483f618b23110b82c7e966fdd6f8959d6723f2eda58a
```

PE properties:

```text
Machine:        x86-64 PE32+
ImageBase:      0x140000000
Entry RVA:      0x1be0
SizeOfImage:    0x4000
Mitigations:    ASLR, high entropy VA, NX
CFG:            no main executable load config
Sections:       .text RX, .rdata R, .pdata R
```

Imports quan trọng:

```text
KERNEL32!ReadFile        IAT RVA 0x2000
KERNEL32!WriteFile       IAT RVA 0x2018
KERNEL32!CreateFileW     IAT RVA 0x2020
KERNEL32!CloseHandle     IAT RVA 0x2028
KERNEL32!HeapAlloc       IAT RVA 0x2030
KERNEL32!GetFileSize     IAT RVA 0x2038
SHELL32!CommandLineToArgvW IAT RVA 0x2050
```

## Reverse VM

`main` nằm tại `base+0x1be0`.

Luồng chính:

- Parse command line bằng `GetCommandLineW` và `CommandLineToArgvW`.
- Allocate zeroed VM context: `HeapAlloc(GetProcessHeap(), 9, 0x20110)`.
- Mở payload file bằng `CreateFileW`.
- Reject nếu size lớn hơn `0x10000`.
- Read payload vào `ctx+0x110`.
- Set `ctx->pc = ctx+0x110`.
- Set guest `sp = (ctx+0x2010f) & ~0xf`.
- Gọi interpreter `execute(ctx)` tại `base+0x1000`.
- Return address sau call là `base+0x1ccc`.

Layout context:

```text
ctx+0x00              guest pc, host pointer
ctx+0x10 + 8*n        guest register x[n]
ctx+0x18              x1 / ra
ctx+0x20              x2 / sp
ctx+0x60              x10 / a0
ctx+0x98              x17 / a7
ctx+0x110             guest code/data buffer
```

`execute` là interpreter loop. Mỗi vòng nó zero `x0`, fetch 32-bit instruction từ `[ctx->pc]`, decode opcode/funct và dispatch.

Các instruction load/store như `LB/LBU/LH/LHU/LW/LWU/LD` và `SB/SH/SW/SD` dereference địa chỉ guest trực tiếp như host address. Không có check vùng nhớ, không có translate, không có sandbox.

Syscall:

```text
a7 = 0x5d  return 0 from execute
a7 = 100   print_char_string(a0)
a7 = 101   print_u64_hex(a0)
a7 = 102   print_u64(a0)
a7 = 103   print newline
other      return 2
```

`print_char_string` cũng dùng `a0` như host pointer. Nó tự scan tới byte NUL rồi gọi `WriteFile(GetStdHandle(-11), a0, len, ...)`.

## Primitive

Các payload probe ban đầu chứng minh:

- `auipc` leak được host pointer của guest code.
- `ctx = pc - 0x110` đọc được context.
- Guest store có thể ghi heap host.
- Dereference địa chỉ không mapped gây access violation `0xc0000005`; trong WSL thấy exit code thấp là `5`.
- Main image base không cố định vì ASLR, nhưng có thể tìm động bằng cách scan pointer quanh heap và validate `MZ`/`PE`.
- IAT main nằm trong `.rdata`, ghi vào IAT crash vì page read-only.
- Host stack pointer xuất hiện trong metadata quanh heap; có thể scan stack page để tìm return address `base+0x1ccc`.

## ASLR bypass

Payload không hardcode base address.

Tìm main base:

- Bắt đầu từ `ctx`.
- Scan vùng heap metadata gần đó.
- Lọc pointer canonical dạng `0x00007...`, page-aligned.
- Dereference candidate, kiểm tra `MZ`.
- Đọc `e_lfanew`, kiểm tra `PE\0\0`.
- Kiểm tra `SizeOfImage >= 0x3000`.
- Kiểm tra string import `"KERN"` ở offset cố định trong bản binary để phân biệt main module với DLL khác.

Tìm return slot:

- Tính expected return value `main_base + 0x1ccc`.
- Scan các stack pointer candidate.
- Chỉ scan trong page hiện tại để tránh guard/unmapped page.
- Match slot chứa `main_base+0x1ccc`.
- Siết thêm điều kiện để tránh stale stack copy:
  - `[slot-8] == ctx` vì saved `rbx` của `execute` hiện tại là context.
  - `[slot-24] == ctx+0x110` vì saved `rsi` của `execute` hiện tại trỏ guest code.

Resolve API:

- Đọc `CreateFileW` từ main IAT `main_base+0x2020`.
- Page-align và scan ngược tới `MZ` để tìm `kernel32` base.
- Parse import table của `kernel32`.
- Descriptor `ntdll.dll` cho ta một resolved thunk pointer trong `ntdll`.
- Scan ngược pointer đó tới `ntdll` base.
- Trong cùng descriptor, tìm name thunk `RtlExitUserProcess` và lấy resolved FirstThunk.
- Scan `.text` của `ntdll` để tìm gadget `pop rcx; ret`.

## Control flow hijack

Không cần ghi IAT. Ta ghi trực tiếp vào native stack frame của `execute`.

`execute` prologue:

```asm
push rbx
push rbp
push rsi
push rdi
sub  rsp, 0x58
```

Epilogue syscall exit:

```asm
add rsp, 0x58
pop rdi
pop rsi
pop rbp
pop rbx
ret
```

Payload overwrite:

```text
[ret_slot-0x20] = fake_file_context    saved rdi
[ret_slot-0x08] = fake_file_context    saved rbx
[ret_slot+0x00] = main_base+0x1c37     return address
```

Khi guest gọi syscall exit, native `execute` return vào `main+0x1c37`.

Đoạn `main+0x1c37` vốn là file-loader của chương trình:

- Lấy path từ `[rdi+8]`.
- Gọi `CreateFileW`.
- Gọi `GetFileSize`.
- Gọi `ReadFile(handle, rbx+0x110, size, ...)`.
- Gọi `CloseHandle`.
- Set `rbx->pc = rbx+0x110`.
- Gọi `execute(rbx)`.

Ta set:

```text
fake_file_context+0x08 = L"C:\\chall\\flag.txt"
```

Vậy code host tự đọc flag vào:

```text
fake_file_context+0x110
```

File flag không phải guest code hợp lệ nên nested `execute(fake_file_context)` return invalid-instruction nhanh, nhưng buffer flag vẫn còn nguyên.

## Printing flag

Payload dựng context thứ hai:

```text
print_context+0x00 = print_code
print_context+0x60 = fake_file_context+0x110   ; guest a0
```

`print_code` chỉ có:

```asm
li a7, 100
ecall
li a7, 0x5d
ecall
```

ROP chain sau epilogue `main`:

```text
pop rcx; ret
rcx = print_context
ret alignment gadget
execute
pop rcx; ret
rcx = 0
ret alignment gadget
RtlExitUserProcess
```

Kết quả là VM syscall `100` in flag buffer ra stdout của process remote.

## Payload

Payload final được generate bằng encoder RV64IM thủ công trong `build_payload.py`, không phụ thuộc guest libc, relocation, compressed instruction hay floating point.

Build:

```bash
python3 build_payload.py final_exploit -o exploit.bin
```

Local validation dùng path tương đối `flag.txt` nhưng giữ nguyên exploit chain:

```bash
python3 build_payload.py local_exploit -o local_exploit.bin
./RV64VMv4.exe local_exploit.bin
```

Output local:

```text
FLAG{RISC_It_for_the_Biscuit_Demo_Flag}
```

## Remote protocol

Service không nhận raw binary. Khi gửi payload debug bằng raw, server trả prompt:

```text
Enter payload encoded in Base64:
```

Vì vậy solver gửi một dòng Base64 qua TLS/SNI.

Run:

```bash
python3 solve.py REMOTE --host ristbiscreal-d2a977a477d7.inst.omnictf.com --port 1337
```

Output:

```text
Enter payload encoded in Base64: [*] Decoding and writing to exploit.bin...
[*] Raw payload size: 1404
OmniCTF{4llIn_Du3_T1me!-ash9+ujdsmnA1}
```

## Files chính

```text
RV64VMv4.exe
RV64VMv4.pdb
build_payload.py
exploit.bin
local_exploit.bin
solve.py
analyze_vm.py
README.md
analysis_notes.md
writeup.md
payload/
prime/
```

Các payload probe/debug trung gian đã được dọn khỏi workspace; logic probe vẫn còn trong `build_payload.py` nếu cần regenerate.
