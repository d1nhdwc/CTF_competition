# Dont RISC It Just Yet Writeup

## TL;DR

Flag:

```text
OmniCTF{CH4S1nG_A1ML3SSLy,.3751sk01L}
```

Final exploit:

```sh
HOST=dontriscyet-570dda073a0a.inst.omnictf.com python3 exploit.py REMOTE
```

The exploit does not brute-force ASLR. It leaks/discovers the runtime base
inside one VM execution, then prints the string at `RV64VMv4.exe + 0x23cb`.

## Challenge Behavior

The challenge binary is a Windows PE64 RISC-V VM. The description says the
flag is stored at:

```text
RV64VMv4.exe + 0x23cb
```

Remote stdout is filtered by `SocketHandler.py`: only a line containing the
flag pattern is returned. Debug leaks through VM stdout are therefore not
useful remotely.

The local binary contains a placeholder flag:

```text
OmniCTF{RealFlagOnRemote}
```

Parsing the PE showed:

```text
placeholder file offset = 0x15cb
section .rdata raw ptr  = 0x1200
section .rdata RVA      = 0x2000
flag RVA                = 0x23cb
```

## Bug

The VM loads guest code into a heap allocation:

```text
vm struct      = heap base
guest code     = vm + 0x110
guest pc       = [vm + 0x00]
guest regs     = vm + 0x10
guest sp       = around vm + 0x20100
```

The important bug is that guest load/store instructions use host pointers
directly. For example, `ld` and `lbu` dereference:

```text
guest_reg + imm
```

without checking that the address is inside guest memory. This gives arbitrary
read from the host process address space as long as the address is mapped.

The VM exposes useful syscalls:

```text
a7 = 93   exit
a7 = 100  print C string from a0
a7 = 101  print u64 hex
a7 = 102  print u64 decimal
a7 = 103  print newline
```

So, if the payload can compute the runtime address
`image_base + 0x23cb`, it can call syscall `100` and print the flag.

## ASLR Problem

Using the PE preferred image base `0x140000000` fails because the binary is
loaded with ASLR. Hardcoding the local runtime base also fails on remote.

Brute-forcing candidate image bases over many remote connections was avoided.
The final payload recovers the base during a single guest execution.

## Base Leak

The guest can get a host pointer to itself with `auipc`:

```text
pc = auipc(0)
vm = pc - 0x110
```

Reading just past the VM allocation revealed heap metadata that points into
loader bookkeeping:

```text
root = *(vm + 0x20128)
```

Locally, `root + 0x218` reaches a `LDR_DATA_TABLE_ENTRY`-like structure for a
loaded system module. The entry layout matches the normal Windows loader list:

```text
+0x00  InLoadOrderLinks.Flink
+0x08  InLoadOrderLinks.Blink
+0x30  DllBase
+0x50  FullDllName.Buffer
+0x60  BaseDllName.Buffer
```

Walking `Blink` four times reaches the main executable entry, where:

```text
entry + 0x30 = RV64VMv4.exe runtime base
```

The payload also includes a few fallback candidates from the same loader area.
For each candidate, it computes:

```text
candidate_flag = candidate_base + 0x23cb
```

Then it checks the bytes for the local prefix `OmniCTF{`. Only if the prefix
matches does it call `print_char_string(candidate_flag)`.

This makes the remote output pass the wrapper filter and avoids printing random
mapped memory.

## Result

Local test:

```sh
python3 exploit.py
./RV64VMv4.exe exploit.bin
```

Output:

```text
OmniCTF{RealFlagOnRemote}
```

Remote test:

```sh
HOST=dontriscyet-570dda073a0a.inst.omnictf.com python3 exploit.py REMOTE
```

Output:

```text
OmniCTF{CH4S1nG_A1ML3SSLy,.3751sk01L}
```
