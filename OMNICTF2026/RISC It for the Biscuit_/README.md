# RISCBiscReal Exploit

## Root cause

The VM stores guest PC and registers as host virtual addresses and performs guest load/store/fetch directly on those addresses. There is no MMU or bounds check, so RV64 guest code has arbitrary host read/write inside the process.

## Exploit strategy

The exploit does not hardcode ASLR addresses. It leaks the current VM context with `auipc`, scans host heap metadata to find the main PE base, finds the live `execute()` return slot on the native stack, resolves `kernel32`/`ntdll` through PE metadata, and overwrites the current `execute()` frame.

Control returns into `main+0x1c37`, reusing the program's own `CreateFileW`/`ReadFile` loader path to read `C:\chall\flag.txt` into a fake VM context. A ROP chain then calls `execute(print_context)`, whose guest code runs syscall `100` to print the flag buffer and syscall `0x5d` to return. The final tail calls `RtlExitUserProcess(0)`.

Important offsets for `RV64VMv4.exe` SHA-256 `4a8a472ebdbbdb48bb1c54f08975785ae8756b4d10066e0676b9e92f61bce3bd`:

- `execute`: `base+0x1000`
- reusable file-reader block: `base+0x1c37`
- return after `execute(ctx)`: `base+0x1ccc`
- plain `ret` alignment gadget: `base+0x1139`
- `CreateFileW` IAT RVA: `0x2020`

## Files

- `build_payload.py`: manual RV64IM encoder, probes, final exploit generator.
- `exploit.bin`: final payload for remote `C:\chall\flag.txt`.
- `local_exploit.bin`: same exploit with local relative `flag.txt` path.
- `solve.py`: local/remote runner, Base64-over-TLS by default.
- `analyze_vm.py`: PE analysis helper.
- `analysis_notes.md`: detailed reverse engineering notes and proof payloads.
- `payload/`: build wrappers, linker sample, source note, and payload binaries.

## Build

```bash
python3 build_payload.py final_exploit -o exploit.bin
python3 build_payload.py local_exploit -o local_exploit.bin
sh payload/build.sh
```

The payload is generated manually to avoid guest libc, relocations, compressed instructions, or toolchain assumptions. It uses only RV64IM instructions.

## Local test

```bash
./RV64VMv4.exe local_exploit.bin
```

Observed local result:

```text
FLAG{RISC_It_for_the_Biscuit_Demo_Flag}
```

`exploit.bin` uses `C:\chall\flag.txt`; that path is not created locally due workspace constraints, so the remote-path payload exits cleanly with no output in this workspace.

## Remote

Default target in `solve.py` is the latest supplied instance:

```bash
python3 solve.py REMOTE
```

Override:

```bash
python3 solve.py REMOTE --host ristbiscreal-d2a977a477d7.inst.omnictf.com --port 1337
```

The service prompts `Enter payload encoded in Base64:`. `solve.py` therefore sends one Base64 line over TLS with SNI by default.

Observed remote result on `ristbiscreal-d2a977a477d7.inst.omnictf.com:1337`:

```text
OmniCTF{4llIn_Du3_T1me!-ash9+ujdsmnA1}
```

## Stability

The exploit is ASLR-aware and validates the current `execute()` frame by saved registers, not only by a copied return address. It depends on the VM executable matching the analyzed version and on normal Windows x64 loader/import behavior. The local exploit prints the demo flag and exits with code 0.
