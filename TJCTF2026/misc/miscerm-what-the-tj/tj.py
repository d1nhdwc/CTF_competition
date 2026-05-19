from pwn import *

def main():
    io = remote('tjc.tf', 31003)

    io.sendlineafter(b'opened?\nYour answer: ', b'1964')
    io.sendlineafter(b'code?\nYour answer: ', b'I will uphold academic and personal integrity in the TJ community')
    io.sendlineafter(b'dollars?\nYour answer: ', b'200')
    io.sendlineafter(b'year?\nYour answer: ', b'Clash Royale')
    io.sendlineafter(b'Lab?\nYour answer: ', b'Marine Biology')
    io.sendlineafter(b'year?\nYour answer: ', b'Gabriel Chapman Asel')
    io.sendlineafter(b'the CEO of?\nYour answer: ', b'Robinhood')
    io.sendlineafter(b'TJ next year?\nYour answer: ', b'34')
    io.sendlineafter(b'campus?\nYour answer: ', b'30')
    io.sendlineafter(b'107 in?\nYour answer: ', b'Gandhi')
    io.sendlineafter(b'music wing?\nYour answer: ', b'13')
    io.sendlineafter(b'pool located?\nYour answer: ', b'Library')
    io.sendlineafter(b'located in?\nYour answer: ', b'Einstein')
    io.sendlineafter(b'at TJ?\nYour answer: ', b'Chhabra')
    io.sendlineafter(b'secret message?\nYour answer: ', b'elevator')
    io.sendlineafter(b'phrase located?\nYour answer: ', b'203')
    io.sendlineafter(b'dollars?\nYour answer: ', b'100')
    io.sendlineafter(b'Supercomputer?\nYour answer: ', b'Blue Glazed Terracotta')


    io.interactive()

if __name__ == '__main__':
    main()
