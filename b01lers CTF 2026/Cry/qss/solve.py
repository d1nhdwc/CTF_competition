#!/usr/bin/env python3
from pwn import *
import json
import math
import re
import numpy as np

HOST = "qss.opus4-7.b01le.rs"
PORT = 8443

context.log_level = "error"

# --------------------------------------------------
# Attack parameters
# --------------------------------------------------
A = 1.093067629216724
B = -0.35686192071075196
C = -0.8409443487682413
D = 0.17900685451225407

# steer total announced bases to stay reasonably balanced
TARGET_TOTAL_Z = 58


# --------------------------------------------------
# Bell / logical states
# --------------------------------------------------
def bell_states():
    phi_minus = np.array([1, 0, 0, -1], dtype=np.complex128) / math.sqrt(2.0)
    psi_plus = np.array([0, 1, 1, 0], dtype=np.complex128) / math.sqrt(2.0)
    return phi_minus, psi_plus


def idx(a, b, c):
    return (a << 2) | (b << 1) | c


def normalized_output_states():
    n = 1.0 / math.sqrt(A * A + B * B + C * C + D * D)

    psi0 = np.zeros(8, dtype=np.complex128)
    psi1 = np.zeros(8, dtype=np.complex128)

    # U(|0_L>|0>) = N(a|000> + b|011> + c|101> + d|110>)
    psi0[idx(0, 0, 0)] = n * A
    psi0[idx(0, 1, 1)] = n * B
    psi0[idx(1, 0, 1)] = n * C
    psi0[idx(1, 1, 0)] = n * D

    # U(|1_L>|0>) = N(a|111> + b|100> + c|010> + d|001>)
    psi1[idx(1, 1, 1)] = n * A
    psi1[idx(1, 0, 0)] = n * B
    psi1[idx(0, 1, 0)] = n * C
    psi1[idx(0, 0, 1)] = n * D

    return psi0, psi1


def complete_basis(vectors, dim=8):
    basis = []
    for v in vectors:
        w = v.astype(np.complex128).copy()
        for b in basis:
            w -= np.vdot(b, w) * b
        nw = np.linalg.norm(w)
        if nw > 1e-12:
            basis.append(w / nw)

    for i in range(dim):
        e = np.zeros(dim, dtype=np.complex128)
        e[i] = 1.0
        w = e.copy()
        for b in basis:
            w -= np.vdot(b, w) * b
        nw = np.linalg.norm(w)
        if nw > 1e-12:
            basis.append(w / nw)

    return basis


def build_unitary():
    phi_minus, psi_plus = bell_states()
    anc0 = np.array([1, 0], dtype=np.complex128)

    in0 = np.kron(phi_minus, anc0)
    in1 = np.kron(psi_plus, anc0)

    out0, out1 = normalized_output_states()

    Vin = np.column_stack(complete_basis([in0, in1], 8))
    Vout = np.column_stack(complete_basis([out0, out1], 8))

    U = Vout @ Vin.conj().T

    # clean numerical dust
    U.real[abs(U.real) < 1e-15] = 0.0
    U.imag[abs(U.imag) < 1e-15] = 0.0
    return U


def encode_complex(z):
    z = complex(z)
    if abs(z.imag) < 1e-15:
        return float(z.real)
    if abs(z.real) < 1e-15:
        return f"{z.imag:.16f}j"
    return f"{z.real:.16f}{z.imag:+.16f}j"


def matrix_to_jsonable(U):
    return [[encode_complex(U[i, j]) for j in range(8)] for i in range(8)]


# --------------------------------------------------
# Robust I/O helpers
# --------------------------------------------------
def recv_nonempty_line(io, timeout=5):
    while True:
        line = io.recvline(timeout=timeout)
        if not line:
            raise EOFError("EOF while waiting for line")
        s = line.decode(errors="ignore").strip()
        if s:
            return s


def recv_prompt(io, prompt: bytes, timeout=5):
    # server uses print(prompt), so prompt ends with '\n'
    io.recvuntil(prompt + b"\n", timeout=timeout)


# --------------------------------------------------
# Strategy
# --------------------------------------------------
def choose_announce_basis(is_test, z_count, valid_z, valid_x):
    if is_test:
        # force enough valid checks on both bases first
        if valid_x < 2:
            return "x"
        if valid_z < 2:
            return "z"
        # then steer toward overall balance
        return "z" if z_count < TARGET_TOTAL_Z else "x"
    else:
        return "z" if z_count < TARGET_TOTAL_Z else "x"


def measurement_plan_for_set(public_set_line):
    if "S0" in public_set_line:
        return [["b", "z"]]
    return [["b", "x"]]


def guess_from_measurement(line):
    if not line.startswith("measurement_outcomes:"):
        raise ValueError(f"Unexpected outcome line: {line!r}")
    m = re.search(r"\bb:[zx]=([01])\b", line)
    if not m:
        raise ValueError(f"Could not parse Bob measurement from: {line!r}")
    return int(m.group(1))


# --------------------------------------------------
# One attempt
# --------------------------------------------------
def run_once(host, port, unitary_json):
    io = remote(host, port, ssl=True)

    recv_prompt(io, b"ancilla_statevector_json>")
    io.sendline(json.dumps([1, 0]).encode())

    recv_prompt(io, b"unitary_8x8_json>")
    io.sendline(json.dumps(unitary_json).encode())

    z_count = 0
    x_count = 0
    valid_z = 0
    valid_x = 0

    transcript = []

    for _ in range(96):
        block = io.recvuntil(b"pre_public_announce_json>\n").decode(errors="ignore")
        transcript.append(block)

        m = re.search(r"round_type:\s*(test|info)", block)
        if not m:
            raise ValueError(f"Could not parse round_type from:\n{block}")
        is_test = (m.group(1) == "test")

        basis = choose_announce_basis(is_test, z_count, valid_z, valid_x)
        if basis == "z":
            z_count += 1
        else:
            x_count += 1

        announce = {"basis": basis, "outcome": 0}
        io.sendline(json.dumps(announce).encode())

        public_set_line = recv_nonempty_line(io)
        public_alice_basis_line = recv_nonempty_line(io)
        transcript.append(public_set_line + "\n")
        transcript.append(public_alice_basis_line + "\n")

        if is_test:
            check_line = recv_nonempty_line(io)
            transcript.append(check_line + "\n")
            if check_line.endswith("yes"):
                if basis == "z":
                    valid_z += 1
                else:
                    valid_x += 1
            continue

        keep_line = recv_nonempty_line(io)
        transcript.append(keep_line + "\n")

        if keep_line.endswith("no"):
            continue

        recv_prompt(io, b"measurement_plan_json>")
        plan = measurement_plan_for_set(public_set_line)
        io.sendline(json.dumps(plan).encode())

        outcome_line = recv_nonempty_line(io)
        transcript.append(outcome_line + "\n")
        guess = guess_from_measurement(outcome_line)

        recv_prompt(io, b"secret_guess_bit>")
        io.sendline(str(guess).encode())

    tail = io.recvall(timeout=2).decode(errors="ignore")
    transcript.append(tail)
    io.close()

    text = "".join(transcript)
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    last = lines[-1] if lines else ""

    success = not last.startswith("No flag yet") and not last.startswith("ABORT")
    return success, last, text


# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    U = build_unitary()
    unitary_json = matrix_to_jsonable(U)

    attempt = 0
    while True:
        attempt += 1
        try:
            ok, last, full = run_once(HOST, PORT, unitary_json)
            print(f"[attempt {attempt}] {last}")
            if ok:
                print("\nFLAG:")
                print(last)
                break
        except EOFError:
            print(f"[attempt {attempt}] EOF, retrying...")
        except Exception as e:
            print(f"[attempt {attempt}] error: {e}, retrying...")


if __name__ == "__main__":
    main()