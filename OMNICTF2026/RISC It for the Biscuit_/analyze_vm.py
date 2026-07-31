#!/usr/bin/env python3
import argparse
import hashlib
import re
import struct
from pathlib import Path


def u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


DLL_FLAGS = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}


class PE:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError("not a PE/MZ file")
        self.pe = u32(self.data, 0x3C)
        if self.data[self.pe:self.pe + 4] != b"PE\0\0":
            raise ValueError("bad PE signature")
        self.machine = u16(self.data, self.pe + 4)
        self.nsects = u16(self.data, self.pe + 6)
        self.timedate = u32(self.data, self.pe + 8)
        self.opt_size = u16(self.data, self.pe + 20)
        self.characteristics = u16(self.data, self.pe + 22)
        self.opt = self.pe + 24
        self.magic = u16(self.data, self.opt)
        self.is_pe64 = self.magic == 0x20B
        if not self.is_pe64:
            raise ValueError("script expects PE32+")
        self.linker = (self.data[self.opt + 2], self.data[self.opt + 3])
        self.entry_rva = u32(self.data, self.opt + 16)
        self.image_base = u64(self.data, self.opt + 24)
        self.section_alignment = u32(self.data, self.opt + 32)
        self.file_alignment = u32(self.data, self.opt + 36)
        self.size_image = u32(self.data, self.opt + 56)
        self.subsystem = u16(self.data, self.opt + 68)
        self.dll_chars = u16(self.data, self.opt + 70)
        self.num_dirs = u32(self.data, self.opt + 108)
        self.sections = []
        soff = self.opt + self.opt_size
        for i in range(self.nsects):
            off = soff + i * 40
            name = self.data[off:off + 8].split(b"\0", 1)[0].decode("latin1")
            self.sections.append({
                "name": name,
                "vsize": u32(self.data, off + 8),
                "rva": u32(self.data, off + 12),
                "raw_size": u32(self.data, off + 16),
                "raw": u32(self.data, off + 20),
                "chars": u32(self.data, off + 36),
            })

    def directory(self, idx):
        if idx >= self.num_dirs:
            return (0, 0)
        off = self.opt + 112 + idx * 8
        return (u32(self.data, off), u32(self.data, off + 4))

    def rva_to_off(self, rva):
        for sec in self.sections:
            start = sec["rva"]
            end = start + max(sec["vsize"], sec["raw_size"])
            if start <= rva < end:
                return sec["raw"] + (rva - start)
        if rva < len(self.data):
            return rva
        return None

    def cstr(self, off):
        end = self.data.find(b"\0", off)
        if end < 0:
            end = min(len(self.data), off + 256)
        return self.data[off:end].decode("latin1", "replace")

    def imports(self):
        rva, _ = self.directory(1)
        off = self.rva_to_off(rva)
        if not rva or off is None:
            return []
        out = []
        idx = 0
        while off + idx * 20 + 20 <= len(self.data):
            d = off + idx * 20
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", self.data, d)
            if not any((oft, name_rva, ft)):
                break
            noff = self.rva_to_off(name_rva)
            dll = self.cstr(noff) if noff is not None else f"<bad {name_rva:#x}>"
            funcs = []
            thunk_rva = oft or ft
            toff = self.rva_to_off(thunk_rva)
            if toff is not None:
                j = 0
                while toff + j * 8 + 8 <= len(self.data):
                    val = u64(self.data, toff + j * 8)
                    if val == 0:
                        break
                    if val >> 63:
                        funcs.append((f"ord_{val & 0xffff}", ft + j * 8))
                    else:
                        ino = self.rva_to_off(val)
                        name = self.cstr(ino + 2) if ino is not None else f"<bad {val:#x}>"
                        funcs.append((name, ft + j * 8))
                    j += 1
            out.append((dll, funcs))
            idx += 1
        return out

    def exports(self):
        rva, _ = self.directory(0)
        off = self.rva_to_off(rva)
        if not rva or off is None:
            return []
        num_names = u32(self.data, off + 24)
        names_rva = u32(self.data, off + 32)
        ord_rva = u32(self.data, off + 36)
        funcs_rva = u32(self.data, off + 28)
        names_off = self.rva_to_off(names_rva)
        ord_off = self.rva_to_off(ord_rva)
        funcs_off = self.rva_to_off(funcs_rva)
        if None in (names_off, ord_off, funcs_off):
            return []
        out = []
        for i in range(num_names):
            no = self.rva_to_off(u32(self.data, names_off + i * 4))
            name = self.cstr(no) if no is not None else "<bad>"
            ordinal = u16(self.data, ord_off + i * 2)
            frva = u32(self.data, funcs_off + ordinal * 4)
            out.append((name, frva))
        return out


def ascii_strings(data, min_len=5):
    pat = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    for m in re.finditer(pat, data):
        yield m.start(), m.group().decode("latin1", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pe", nargs="?", default="RV64VMv4.exe")
    ap.add_argument("--find", default="OmniCTF{RealFlagOnRemote}")
    args = ap.parse_args()

    pe = PE(args.pe)
    h = hashlib.sha256(pe.data).hexdigest()
    print(f"path: {pe.path}")
    print(f"sha256: {h}")
    print(f"machine: {pe.machine:#x} ({'x86_64' if pe.machine == 0x8664 else 'unknown'})")
    print(f"linker: {pe.linker[0]}.{pe.linker[1]}")
    print(f"image_base: {pe.image_base:#x}")
    print(f"entry: rva={pe.entry_rva:#x} va={pe.image_base + pe.entry_rva:#x}")
    print(f"size_of_image: {pe.size_image:#x}")
    flags = [name for bit, name in DLL_FLAGS.items() if pe.dll_chars & bit]
    print(f"dll_characteristics: {pe.dll_chars:#x} {' '.join(flags)}")
    lc_rva, lc_size = pe.directory(10)
    print(f"load_config: rva={lc_rva:#x} size={lc_size:#x}")
    print("sections:")
    for sec in pe.sections:
        va = pe.image_base + sec["rva"]
        print(
            f"  {sec['name']:<8} rva={sec['rva']:#06x} va={va:#x} "
            f"vsize={sec['vsize']:#x} raw={sec['raw']:#x}/{sec['raw_size']:#x} "
            f"chars={sec['chars']:#x}"
        )
    print("imports:")
    for dll, funcs in pe.imports():
        print(f"  {dll}")
        for name, iat_rva in funcs:
            print(f"    {iat_rva:#06x} {name}")
    exps = pe.exports()
    print(f"exports: {len(exps)}")
    for name, rva in exps[:40]:
        print(f"  {rva:#x} {name}")
    needle = args.find.encode("latin1", "ignore")
    pos = pe.data.find(needle)
    if pos >= 0:
        rva = None
        for sec in pe.sections:
            if sec["raw"] <= pos < sec["raw"] + sec["raw_size"]:
                rva = sec["rva"] + (pos - sec["raw"])
                break
        print(f"needle: off={pos:#x} rva={rva if rva is not None else -1:#x} va={pe.image_base + rva if rva is not None else -1:#x}")
    else:
        print("needle: not found")
    print("interesting strings:")
    for off, s in ascii_strings(pe.data):
        if any(x in s.lower() for x in ("kernel", "flag", "omni", "createfile", ".pdb", "risc")):
            print(f"  {off:#x}: {s}")


if __name__ == "__main__":
    main()
