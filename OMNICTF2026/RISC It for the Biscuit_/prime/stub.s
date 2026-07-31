.section .text
.globl _start, syscall_exit, print_char_string, print_u64_hex, print_u64, print_new_line

_start:
    call run

syscall_exit:
    li a7, 0x5d
    ecall

print_char_string:
    li a7, 100
    ecall
    ret

print_u64_hex:
    li a7, 101
    ecall
    ret

print_u64:
    li a7, 102
    ecall
    ret

print_new_line:
    li a7, 103
    ecall
    ret
