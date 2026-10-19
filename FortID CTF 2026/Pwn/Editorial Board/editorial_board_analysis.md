# Editorial Board — Bug Analysis, Primitives, and Intended Direction

## 1. Overview

This note summarizes the initial pwn analysis for the `editorial_board` challenge. It focuses on the bug, exploit primitives, constraints, and likely exploitation direction. It does **not** include a final solve payload yet.

The challenge combines:

- a strict English text validator,
- a fixed RWX `mmap`,
- a post-validation stack overflow,
- and a text-only payload constraint.

The intended solve appears to require turning an accepted English paragraph into a control-flow hijack.

---

## 2. Binary Triage

Observed binary properties:

```text
file:      ELF 32-bit i386
type:      non-PIE EXEC
stripped:  yes
RELRO:     Full RELRO / BIND_NOW
Canary:    likely disabled
NX:        enabled for stack
RWX mmap:  yes, fixed at 0x656c6000
ASLR:      binary base fixed because non-PIE
```

Relevant addresses:

```text
main                     = 0x0804984a
validate_candidate        = 0x08049310
find_validator_path       = 0x080493fd
run_validator_on_text     = 0x080494ea
show_validator_checksum   = 0x080496cf
mmap_fixed_rwx            = 0x080497d3
copy_stub                 = 0x0804979e
reject                    = 0x080492f0
die_perror                = 0x080492d2

fixed RWX mmap address    = 0x656c6000
fixed RWX mmap size       = 0x10000
mmap protection           = PROT_READ | PROT_WRITE | PROT_EXEC
stack input buffer        = ebp - 0x399
maximum read size         = 0x384
```

---

## 3. Validator Constraints

The validator is strict. Input must pass both structural checks and a LanguageTool grammar/style check.

Important constraints from `validate.py`:

```text
input length:              640..900 bytes
minimum words:             90
minimum sentences:         4
allowed characters:        A-Z a-z space . , ; : ' - ? !
must end with:             . ? !
maximum repetition ratio:  0.1
maximum average sentence:  32 words
minimum score:             88.0
maximum issues per 100:    2.2
maximum spelling issues:   0.0
```

Allowed characters:

```python
ALLOWED = set(string.ascii_letters + " .,;:'-?!")
```

This means the exploit payload cannot directly contain raw addresses, null bytes, slashes, digits, underscores, parentheses, or most normal shellcode bytes.

---

## 4. High-Level Program Flow

Reconstructed flow of `main`:

```c
setvbuf(stdin, NULL, _IONBF, 0);
setvbuf(stdout, NULL, _IONBF, 0);
alarm(45);

buf = mmap(0x656c6000, 0x10000, RWX | MAP_FIXED_PRIVATE_ANON);
memset(buf, 0xff, 0x10000);

show_validator_checksum();

puts("The Editorial Board accepts one English paragraph.");
puts("A compelling piece may be published, AI slop is strictly prohibited!");
puts("Submit your manuscript:");

n = read(0, stack_buf, 0x384);
trim trailing '\n' and '\r';
stack_buf[n] = 0;

if (!run_validator_on_text(stack_buf, n))
    reject();

memcpy(0x656c6000, stack_buf, n);
copy_stub(stack_buf, n);

puts("Typeset, but not persuasive.");
return;
```

Key point:

```text
If the validator accepts the text, the same text is copied into the fixed RWX mapping at 0x656c6000.
```

---

## 5. Root Cause

There is no direct overflow in the initial `read`.

The initial input buffer is large enough:

```text
read size:      0x384 = 900
stack buffer:   about 0x399 = 921
```

The real bug is later, in `copy_stub`.

### Vulnerable function: `copy_stub`

Approximate disassembly:

```asm
0804979e:
  push ebp
  mov ebp, esp
  sub esp, 0x259

  mov esi, [ebp+8]      ; input pointer
  mov ecx, [ebp+0xc]    ; input length
  lea edi, [ebp-0x259]
  rep movsb             ; BUG: no bounds check

  mov ebx, 0x804c020
  mov esi, 0x804c088
  mov ecx, 0x656c6261
  mov edi, 0x656c6261
  xor edx, edx
  xor eax, eax
  leave
  ret
```

Local buffer size:

```text
0x259 = 601 bytes
```

Validator minimum input length:

```text
640 bytes
```

Therefore, every accepted input must overflow `copy_stub`.

---

## 6. Primitive A — Stack Overflow After Validation

Accepted input reaches:

```asm
rep movsb
```

with:

```text
destination = stack local buffer of size 0x259
length      = validated input length, 640..900
```

This gives control over:

```text
saved EBP
saved RET
stack data after saved RET
```

Expected offsets:

```text
offset to saved EBP = 0x259
offset to saved RET = 0x25d
```

So if bytes at input offset `0x25d..0x260` are controlled, they become the return address.

---

## 7. Primitive B — Fixed RWX Landing Zone

Before `copy_stub`, the program copies the entire accepted manuscript to:

```text
0x656c6000
```

This region is:

```text
RWX
fixed address
0x10000 bytes
```

So the manuscript exists twice:

```text
1. on the stack, where it overflows copy_stub
2. in executable memory, at 0x656c6000
```

This is the intended execution target.

---

## 8. Primitive C — Textual Return Address

The address:

```text
0x656c6261
```

has little-endian bytes:

```text
61 62 6c 65
```

which is the ASCII string:

```text
able
```

This is important because `able` is:

```text
- only alphabetic,
- allowed by the validator,
- a valid English word,
- and an address inside the RWX mmap.
```

Therefore, if the bytes at saved RET are:

```text
able
```

then execution returns to:

```text
0x656c6261
```

This lies inside the fixed RWX mapping:

```text
0x656c6261 - 0x656c6000 = 0x261
```

So the CPU begins executing at manuscript offset:

```text
0x261
```

---

## 9. Primitive D — Controlled Registers

Right before `leave; ret`, `copy_stub` sets several registers:

```text
ebx = 0x0804c020
esi = 0x0804c088
ecx = 0x656c6261
edi = 0x656c6261
edx = 0
eax = 0
```

This looks deliberate.

Notably:

```text
ecx = edi = 0x656c6261
```

which is the same `able` address inside the RWX mapping.

Possible use:

```text
- landing address hint,
- decoder pointer,
- writable/executable memory pointer,
- alphanumeric shellcode state setup.
```

---

## 10. Exploit Layout Hypothesis

The likely intended input layout:

```text
[0x000..0x25c]  English paragraph filler that passes validator
[0x25d..0x260]  "able"  -> saved RET = 0x656c6261
[0x261..]       printable / alphanumeric stage1 code
```

After the validated manuscript is copied to RWX memory:

```text
0x656c6000 + 0x000  = manuscript start
0x656c6000 + 0x25d  = "able"
0x656c6000 + 0x261  = stage1 entry point
```

After `copy_stub` returns:

```text
EIP = 0x656c6261
```

Execution starts at the bytes immediately after the textual return address.

---

## 11. Main Exploitation Constraint

The payload must be both:

```text
1. valid English text accepted by validate.py
2. valid machine code or a valid machine-code decoder after EIP lands in RWX memory
```

Allowed byte set:

```text
A-Z a-z space . , ; : ' - ? !
```

This makes normal shellcode impossible directly.

Useful instruction bytes from the allowed set include:

```text
A 0x41  inc ecx
B 0x42  inc edx
C 0x43  inc ebx
D 0x44  inc esp
E 0x45  inc ebp
H 0x48  dec eax
I 0x49  dec ecx
J 0x4a  dec edx
K 0x4b  dec ebx
P 0x50  push eax
Q 0x51  push ecx
R 0x52  push edx
S 0x53  push ebx
T 0x54  push esp
U 0x55  push ebp
X 0x58  pop eax
Y 0x59  pop ecx
Z 0x5a  pop edx
a 0x61  popa
h 0x68  push imm32
j 0x6a  push imm8
- 0x2d  sub eax, imm32
, 0x2c  sub al, imm8
```

This suggests an ASCII / alphanumeric shellcode or decoder.

---

## 12. Possible Exploitation Directions

### Direction 1 — Alphanumeric or Printable i386 Shellcode

Build a stage1 using only allowed bytes.

Goal:

```text
execve("/bin/sh", 0, 0)
```

or:

```text
open/read/write flag
```

Problem:

```text
The allowed charset does not include slash `/`, digits, or raw syscall bytes.
```

So strings and non-printable opcodes need to be constructed or decoded at runtime.

---

### Direction 2 — Printable Decoder

Use the valid English text as a printable decoder.

The decoder could:

```text
1. use allowed opcodes only,
2. write real shellcode into RWX memory,
3. jump to decoded shellcode.
```

Because the memory at `0x656c6000` is RWX, self-modifying code is allowed.

This is likely the clean intended path.

---

### Direction 3 — Textual ROP

Normal ROP is difficult because useful PLT addresses contain disallowed bytes.

Example:

```text
write@plt, read@plt, system@plt, etc.
```

will contain bytes such as:

```text
0x08, 0x04, 0x90
```

which cannot pass the validator.

ROP may still be possible if printable code constructs addresses dynamically, but that becomes equivalent to printable shellcode.

---

## 13. Why `able` Is Likely Intended

`copy_stub` explicitly sets:

```text
ecx = 0x656c6261
edi = 0x656c6261
```

This value decodes to:

```text
able
```

It is also exactly inside the fixed RWX mapping.

That makes it a strong hint:

```text
saved RET = "able"
EIP       = 0x656c6261
```

The challenge title and validator theme also fit this idea: the exploit is a manuscript whose meaningful English content doubles as machine code.

---

## 14. Current Status

Confirmed primitives:

```text
- fixed RWX mapping at 0x656c6000
- accepted input copied into that RWX mapping
- stack overflow in copy_stub after validation
- saved RET offset likely 0x25d
- textual RET value "able" gives EIP = 0x656c6261
- useful registers set before return, especially ecx/edi = 0x656c6261
```

Unconfirmed items:

```text
- exact offset should be verified in GDB
- whether saved EBP must be shaped carefully for leave; ret
- whether validator accepts a paragraph with "able" exactly at offset 0x25d
- exact printable shellcode strategy
- whether a full English-looking decoder can pass LanguageTool
```

---

## 15. Debugging Checklist

Verify offset and control flow:

```gdb
gdb ./editorial_board
set disassembly-flavor intel
b *0x0804979e
b *0x080497ce
run < input.txt
x/80bx $ebp-0x270
x/wx $ebp+4
x/32i 0x656c6261
```

Check mmap contents:

```gdb
x/200bx 0x656c6000
x/32i 0x656c6261
```

Check saved return overwrite:

```gdb
x/wx $ebp+4
```

Expected:

```text
$ebp+4 = 0x656c6261
```

Check execution:

```gdb
si
x/i $eip
```

Expected:

```text
EIP = 0x656c6261
```

---

## 16. Next Steps

Recommended next work:

```text
1. Build a validator-passing paragraph with "able" at offset 0x25d.
2. Verify saved RET becomes 0x656c6261.
3. Disassemble bytes at 0x656c6261.
4. Design a minimal printable stage1.
5. Test whether the stage1 can survive LanguageTool.
6. Convert the stage1 into an English-looking paragraph if necessary.
```

Most likely final path:

```text
English paragraph
→ validator accepts
→ copy to RWX fixed mapping
→ copy_stub stack overflow
→ saved RET = "able"
→ EIP = 0x656c6261
→ printable decoder
→ decoded shellcode
→ read flag / spawn shell
```
