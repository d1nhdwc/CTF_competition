#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

typedef void *(*mmap_fn_t)(void *, size_t, int, int, int, off_t);

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static mmap_fn_t real_mmap = NULL;
    if (!real_mmap) {
        real_mmap = (mmap_fn_t)dlsym(RTLD_NEXT, "mmap");
    }

    const size_t four_gb = 0x100000000ULL;
    const size_t eight_gb = 0x200000000ULL;
    if (addr == NULL && length == four_gb && prot == PROT_NONE &&
        (flags & MAP_PRIVATE) && (flags & MAP_ANONYMOUS)) {
        void *p = real_mmap(addr, eight_gb, prot, flags, fd, offset);
        if (p != MAP_FAILED) {
            return p;
        }
    }

    return real_mmap(addr, length, prot, flags, fd, offset);
}
