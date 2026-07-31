#!/usr/bin/env python3
import argparse
import base64
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path


DEFAULT_HOST = "ristbiscreal-d2a977a477d7.inst.omnictf.com"
DEFAULT_PORT = 1337
FLAG_RE = re.compile(rb"(?:OmniCTF|OMNICTF|FLAG|CTF)\{[ -~]{1,200}\}")


def encode_payload(data, mode):
    if mode == "raw":
        return data
    if mode == "base64-line":
        return base64.b64encode(data) + b"\n"
    if mode == "hex-line":
        return data.hex().encode() + b"\n"
    raise ValueError(f"unknown send mode {mode}")


def run_local(args):
    payload = Path(args.payload)
    exe = Path(args.exe)
    exe_arg = str(exe)
    if not exe.is_absolute() and "/" not in exe_arg and "\\" not in exe_arg:
        exe_arg = f"./{exe_arg}"
    proc = subprocess.run(
        [exe_arg, str(payload)],
        cwd=args.cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.timeout,
        check=False,
    )
    out = proc.stdout + proc.stderr
    sys.stdout.buffer.write(out)
    if out and not out.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    print(f"[local] exit_code={proc.returncode}", file=sys.stderr)
    m = FLAG_RE.search(out)
    return 0 if m else (proc.returncode or 1)


def recv_all(sock, timeout):
    sock.settimeout(timeout)
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


def run_remote_once(args, data):
    ctx = ssl.create_default_context()
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=args.host) as sock:
            sock.settimeout(args.timeout)
            if args.read_banner:
                banner = recv_all(sock, min(args.timeout, 2.0))
                if banner:
                    sys.stderr.write(banner.decode("latin1", "replace"))
            sock.sendall(encode_payload(data, args.send_mode))
            if args.shutdown_send:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            return recv_all(sock, args.timeout)


def run_remote(args):
    data = Path(args.payload).read_bytes()
    last = b""
    for attempt in range(1, args.retries + 1):
        try:
            out = run_remote_once(args, data)
        except Exception as exc:
            print(f"[remote] attempt {attempt}/{args.retries} failed: {exc}", file=sys.stderr)
            if attempt != args.retries:
                time.sleep(args.retry_delay)
            continue
        last = out
        sys.stdout.buffer.write(out)
        if out and not out.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        m = FLAG_RE.search(out)
        if m:
            print(m.group().decode("latin1", "replace"))
            return 0
        print(f"[remote] no flag found on attempt {attempt}", file=sys.stderr)
        if attempt != args.retries:
            time.sleep(args.retry_delay)
    if last:
        print("[remote] raw output above did not match flag regex", file=sys.stderr)
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("LOCAL", "REMOTE"))
    ap.add_argument("--payload", default="exploit.bin")
    ap.add_argument("--exe", default="./RV64VMv4.exe")
    ap.add_argument("--cwd", default=os.getcwd())
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--retry-delay", type=float, default=1.0)
    ap.add_argument("--send-mode", choices=("raw", "base64-line", "hex-line"), default="base64-line")
    ap.add_argument("--read-banner", action="store_true")
    ap.add_argument("--shutdown-send", action="store_true")
    args = ap.parse_args()

    if args.mode == "LOCAL":
        raise SystemExit(run_local(args))
    raise SystemExit(run_remote(args))


if __name__ == "__main__":
    main()
