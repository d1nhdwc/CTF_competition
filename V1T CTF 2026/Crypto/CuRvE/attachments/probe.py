from pwn import *
context.log_level = "error"

io = remote("crypto.v1t.site", 13237)
data = io.recvrepeat(3)
sys_write = sys.stdout.write
sys_write(data.decode(errors="replace"))
sys_write("\n===== sending choice 3 =====\n")
io.sendline(b"3")
data = io.recvrepeat(3)
sys_write(data.decode(errors="replace"))
io.close()
