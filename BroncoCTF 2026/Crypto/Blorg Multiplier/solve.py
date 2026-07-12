#!/usr/bin/env python3
from pwn import *
from pathlib import Path
from subprocess import STDOUT
import hashlib
import re
import shutil
import sys
import time

HOST = args.HOST or "0.cloud.chals.io"
PORT = int(args.PORT or 13758)
SNI_HOST = args.SNI_HOST or "broncoctf-blorg.chals.io"
TIMEOUT = int(args.TIMEOUT or 20)
RETRIES = int(args.RETRIES or 3)

context.log_level = args.LOG_LEVEL or "info"

# Classic 128-byte MD5 collision pair.
# Both messages hash to 79054025255fb1a26e4bc422aef54eb4.
COLLISION_A = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a"
    "085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1e"
    "c69821bcb6a8839396f9652b6ff72a70"
)

COLLISION_B = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a"
    "085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1e"
    "c69821bcb6a8839396f965ab6ff72a70"
)

# 1 -> 2 -> 4 -> 8 -> 16 -> 30 -> 60 -> 118 -> 234 -> 468
PROGRAM_COMMANDS = (
    b"none none none none decrease none decrease decrease none"
)


def verify_collision() -> None:
    digest_a = hashlib.md5(COLLISION_A).digest()
    digest_b = hashlib.md5(COLLISION_B).digest()

    if COLLISION_A == COLLISION_B or digest_a != digest_b:
        raise SystemExit("[-] Embedded MD5 collision pair is invalid")

    if b"\n" in COLLISION_A or b"\n" in COLLISION_B:
        raise SystemExit("[-] Collision message contains a newline byte")


def latin1_to_wire(data: bytes) -> bytes:
    """
    The server does:
        input() -> Unicode string -> encode("latin-1")

    Send the UTF-8 representation of the Latin-1 string so the bytes hashed
    by the checker are exactly `data`.
    """
    return data.decode("latin-1").encode("utf-8")


def connect_plain():
    log.info(f"Trying plain TCP: {HOST}:{PORT}")
    return remote(HOST, PORT, timeout=TIMEOUT)


def connect_snicat():
    sc_path = shutil.which("sc")
    if sc_path is None and Path("./sc").is_file():
        sc_path = "./sc"

    if sc_path is None:
        raise RuntimeError("snicat client `sc` was not found")

    log.info(f"Trying snicat: {sc_path} {SNI_HOST}")
    return process([sc_path, SNI_HOST], stderr=STDOUT)


def connect_tls():
    log.info(f"Trying direct TLS/SNI: {SNI_HOST}:443")
    return remote(
        SNI_HOST,
        443,
        ssl=True,
        sni=SNI_HOST,
        timeout=TIMEOUT,
    )


def connect_local():
    checker = args.CHECKER or "./checker.py"
    log.info(f"Running local checker: {checker}")
    return process([sys.executable, checker], stderr=STDOUT)


def wait_for(io, marker: bytes) -> bytes:
    try:
        data = io.recvuntil(marker, timeout=TIMEOUT)
    except EOFError as exc:
        raise RuntimeError(
            f"connection closed while waiting for {marker!r}"
        ) from exc

    if marker not in data:
        raise RuntimeError(
            f"timeout while waiting for {marker!r}; received {data!r}"
        )

    return data


def exploit(io) -> bytes:
    collision_a_wire = latin1_to_wire(COLLISION_A)
    collision_b_wire = latin1_to_wire(COLLISION_B)

    # Create a programmable command whose name is COLLISION_A.
    wait_for(io, b"> ")
    io.sendline(b"program")

    wait_for(io, b"What is the name of the new command? ")
    io.sendline(collision_a_wire)

    wait_for(
        io,
        b"Which (space separated) commands would you like it to run:"
    )
    io.sendline(PROGRAM_COMMANDS)

    # Invoke COLLISION_A. It reaches exactly 468 blorgs using 3 edits.
    wait_for(io, b"> ")
    io.sendline(collision_a_wire)

    # COLLISION_B has the same MD5 but is not equal to the programmed name.
    # It passes the whitelist, skips every known-command branch, and reaches
    # the flag-printing `else`.
    wait_for(io, b"> ")
    io.sendline(collision_b_wire)

    try:
        data = io.recvuntil(
            b"Wow! You earned the flag: ",
            timeout=TIMEOUT,
        )
    except EOFError as exc:
        raise RuntimeError(
            "server closed before printing the flag"
        ) from exc

    if b"Wow! You earned the flag: " not in data:
        tail = io.recvrepeat(1)
        raise RuntimeError(
            "flag marker was not received:\n"
            + (data + tail).decode(errors="replace")
        )

    flag = io.recvline(timeout=TIMEOUT).strip()
    if not flag:
        raise RuntimeError("flag line was empty")

    return flag


def main() -> None:
    verify_collision()

    if args.LOCAL:
        connectors = [("local", connect_local)]
    else:
        # The challenge publishes both endpoints. Prefer plain nc, then
        # fall back to the official snicat route and direct TLS/SNI.
        connectors = [
            ("plain TCP", connect_plain),
            ("snicat", connect_snicat),
            ("TLS/SNI", connect_tls),
        ]

    errors = []

    for name, connector in connectors:
        for attempt in range(1, RETRIES + 1):
            io = None

            try:
                io = connector()
                flag = exploit(io)
                log.success(f"{name} worked")
                print(f"[+] FLAG: {flag.decode(errors='replace')}")
                io.close()
                return

            except Exception as exc:
                errors.append(f"{name} attempt {attempt}: {exc}")
                log.warning(
                    f"{name} attempt {attempt}/{RETRIES} failed: {exc}"
                )

                if io is not None:
                    try:
                        io.close()
                    except Exception:
                        pass

                if attempt < RETRIES:
                    time.sleep(1)

    raise SystemExit(
        "[-] All connection methods failed:\n  - "
        + "\n  - ".join(errors)
    )


if __name__ == "__main__":
    main()
