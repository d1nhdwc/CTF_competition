#include <stdint.h>

extern void syscall_exit(void);
extern void print_char_string(char* str);
extern void print_u64_hex(uint64_t val);
extern void print_u64(uint64_t val);
extern void print_new_line(void);

// Return the n-th prime (n >= 1). For n == 1, returns 2.
uint64_t find_nth_prime(uint64_t n) {
    if (n == 0) {
        return 0;  // or handle as error
    }

    uint64_t t0 = 1;      // current number being tested
    uint64_t t3 = 0;      // count of primes found

    while (1) {
        t0 += 1;          // next candidate
        int t2 = 0;       // 0 = assume prime, 1 = not prime

        // special case: 2 is prime
        if (t0 == 2) {
            t3 += 1;
            if (t3 == n) {
                return t0;
            }
            continue;
        }

        // check divisors from 2 up to t4*t4 > t0
        uint64_t t4 = 2;
        while (1) {
            uint64_t t1 = t4 * t4;
            if (t1 > t0) {
                break;          // no divisor found
            }
            if (t0 % t4 == 0) { // found a divisor
                t2 = 1;
                break;
            }
            t4 += 1;
        }

        if (t2 == 0) {     // still marked as prime
            t3 += 1;
            if (t3 == n) {
                return t0; // t0 is the n-th prime
            }
        }
    }
}

void run(void) {
    uint64_t nth_prime_number_to_find = 10000;
    uint64_t nth_prime = find_nth_prime(nth_prime_number_to_find);
    print_char_string("The "); 
    print_u64(nth_prime_number_to_find);
    print_char_string("th prime number is: ");
    print_u64(nth_prime);
    print_new_line();
    syscall_exit();
}
