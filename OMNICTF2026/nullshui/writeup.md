# nullshui writeup

## Overview

Binary exposes `alloc / free / view / zero` over 16 slots. The useful properties are:

- PIE + Full RELRO + NX + canary.
- `alloc` does a single `read()` into freshly allocated heap memory.
- `view` prints a pointer with `puts()`.
- `zero` can zero one qword in heap metadata.

The final chain is:

1. leak heap
2. leak libc
3. use stale largebin to get arbitrary allocation
4. leak `environ`
5. write ORW ROP on stack
6. `open("/home/ctf/flag.txt") -> read -> write`

## Heap + libc leaks

Heap is recovered from tcache safe-linking state.
Libc is recovered from the unsorted-bin fd leak.

That gives the two addresses needed for the later arbitrary allocation stage.

## Stale largebin primitive

The main heap primitive is the stale largebin path:

- build a largebin chunk layout
- zero the right nextsize metadata
- force backward consolidation
- reuse stale largebin state to get duplicate allocation and controlled writes

From there the exploit can poison a tcache entry and make `malloc()` return an arbitrary target.

## Stack leak

The stable remote leak is not the `ld` copy path; the final working leak is:

- target: `libc.symbols["environ"] - 0x18`
- write 0x18 bytes of marker data
- `puts()` on that allocation prints the original `environ` pointer

That works because the tcache key zeroing lands before `environ`, not on top of it.

From `environ`:

- saved return for `alloc` sits at `environ - 0x150`
- actual write target is `environ - 0x158`
- first 8 bytes are padding / saved `rbp`
- ROP chain starts immediately after

## ROP chain

The chain is a normal ORW layout:

```text
ret
pop rdi ; ret              -> path
pop rsi ; ret              -> 0
open
xchg rdi, rax ; cld ; ret  -> move returned fd into rdi
pop rsi ; ret              -> buf
pop rdx ; ... ; ret        -> 0x100
read
pop rdi ; ret              -> 1
pop rsi ; ret              -> buf
pop rdx ; ... ; ret        -> 0x100
write
pop rdi ; ret              -> 0
_exit
```

Offsets used in the final exploit are taken from the shipped libc.

The path is placed early on the stack at `stack_target + 0x120`, and the output buffer is at `stack_target + 0x200`.

Local uses `flag.txt`; remote uses `/home/ctf/flag.txt`.

## Run

```bash
python3 rop_orw.py
python3 rop_orw.py REMOTE TIMEOUT=8
```

Final remote flag:

```text
OmniCTF{145963c105e9ed8dbf6d95c06fb552fe63062dcdd885bd4c208a4693b8af8a30}
```
