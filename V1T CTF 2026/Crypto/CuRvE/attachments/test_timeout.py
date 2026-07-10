from pwn import *
import time
context.log_level = "error"
io = remote("crypto.v1t.site", 13237)
io.recvuntil(b"Your choice:")
io.sendline(b"3")
data = io.recvuntil(b"coefficient a (hex):", timeout=10).decode(errors="replace")
# extract prime
for line in data.splitlines():
    if line.strip().startswith("Prime p ="):
        print("GOT PRIME:", line.strip()[:40], "...", flush=True)
print("Now sleeping to test server timeout...", flush=True)
t0=time.time()
for s in (20,40,70,110):
    time.sleep(s-(time.time()-t0))
    print(f"slept ~{int(time.time()-t0)}s, sending a... ", flush=True)
    if s==110:
        io.sendline(b"abcdefabcdefabcdefabcdef1")  # bad a to provoke response
        try:
            r=io.recvrepeat(5).decode(errors="replace")
            print("RESPONSE after %ds:"%int(time.time()-t0), repr(r[:200]), flush=True)
        except Exception as e:
            print("recv err", e, flush=True)
    else:
        # peek if connection still alive without sending real input
        try:
            io.send(b"")  # noop
        except Exception as e:
            print("connection dead at", int(time.time()-t0), e, flush=True)
            break
io.close()
