#define _GNU_SOURCE
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *rend_sock_path(void)
{
#ifdef DEV_MODE
    const char *e = getenv("MEDREC_SOCK");
    if (e) return e;
#endif
    return REND_SOCK;
}

const char *app_dir_path(void)
{
#ifdef DEV_MODE
    const char *e = getenv("MEDREC_DIR");
    if (e) return e;
#endif
    return APP_DIR;
}

ssize_t readn(int fd, void *p, size_t n)
{
    uint8_t *b = p;
    size_t   o = 0;
    while (o < n) {
        ssize_t k = read(fd, b + o, n - o);
        if (k == 0) break;
        if (k < 0) {
            if (errno == EINTR) continue;
            break;
        }
        o += (size_t)k;
    }
    return (ssize_t)o;
}

ssize_t writen(int fd, const void *p, size_t n)
{
    const uint8_t *b = p;
    size_t         o = 0;
    while (o < n) {
        ssize_t k = write(fd, b + o, n - o);
        if (k <= 0) {
            if (k < 0 && errno == EINTR) continue;
            break;
        }
        o += (size_t)k;
    }
    return (ssize_t)o;
}

void wr(int fd, const void *p, size_t n)  { (void)writen(fd, p, n); }
void wrstr(int fd, const char *s)         { wr(fd, s, strlen(s)); }

void wrf(int fd, const char *fmt, ...)
{
    char    b[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof b) n = (int)sizeof b - 1;
    wr(fd, b, (size_t)n);
}

void rb_init(struct rdbuf *rb, int fd)
{
    rb->fd = fd;
    rb->len = 0;
    rb->pos = 0;
}

static int rb_getc(struct rdbuf *rb)
{
    if (rb->pos >= rb->len) {
        ssize_t k = read(rb->fd, rb->buf, sizeof rb->buf);
        if (k <= 0) return -1;
        rb->len = (size_t)k;
        rb->pos = 0;
    }
    return (unsigned char)rb->buf[rb->pos++];
}

int rb_readline(struct rdbuf *rb, char *out, size_t cap)
{
    size_t i = 0;
    for (;;) {
        int c = rb_getc(rb);
        if (c < 0) return -1;
        if (c == '\n') break;
        if (c == '\r') continue;
        if (i + 1 < cap) out[i++] = (char)c;
    }
    out[i] = 0;
    return (int)i;
}

void send_data(int fd, const void *p, size_t n)
{
    const uint8_t *b = p;
    char           hdr[64];
    int            hn = snprintf(hdr, sizeof hdr, "DATA %zu ", n);
    wr(fd, hdr, (size_t)hn);

    char   hex[4096 * 2 + 1];
    size_t off = 0;
    while (off < n) {
        size_t k = n - off;
        if (k > 4096) k = 4096;
        bin2hex(b + off, k, hex);
        wr(fd, hex, k * 2);
        off += k;
    }
    wr(fd, "\n", 1);
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t hex2bin(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex);
    if (n & 1) return 0;
    n /= 2;
    if (n > cap) n = cap;
    for (size_t i = 0; i < n; i++) {
        int a = hexval((unsigned char)hex[2 * i]);
        int b = hexval((unsigned char)hex[2 * i + 1]);
        if (a < 0 || b < 0) return 0;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return n;
}

void bin2hex(const uint8_t *in, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 15];
    }
    out[2 * n] = 0;
}

int is_hex(const char *s, size_t want_chars)
{
    if (strlen(s) != want_chars) return 0;
    for (size_t i = 0; i < want_chars; i++)
        if (hexval((unsigned char)s[i]) < 0) return 0;
    return 1;
}

int ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    uint8_t        d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(x[i] ^ y[i]);
    return d != 0;
}

void rand_hex(char *out, size_t nhex)
{
    static const char H[] = "0123456789abcdef";
    uint8_t           r[64];
    size_t            need = (nhex + 1) / 2;
    if (need > sizeof r) need = sizeof r;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        (void)readn(fd, r, need);
        close(fd);
    } else {
        for (size_t i = 0; i < need; i++) r[i] = (uint8_t)rand();
    }
    for (size_t i = 0; i < nhex; i++) out[i] = H[(r[i / 2] >> ((i & 1) ? 0 : 4)) & 15];
    out[nhex] = 0;
}

int split(char *line, char *tok[], int maxtok)
{
    int n = 0;
    char *p = line;
    while (*p && n < maxtok) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[n++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    return n;
}

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
               ((uint32_t)p[4*i+2] << 8) | (uint32_t)p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void sha256(const uint8_t *d, size_t n, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                     0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha256_block(h, d + i);

    uint8_t tail[128];
    size_t  r = n - i;
    memcpy(tail, d + i, r);
    tail[r++] = 0x80;
    size_t total = (r <= 56) ? 64 : 128;
    memset(tail + r, 0, total - r - 8);
    uint64_t bits = (uint64_t)n * 8;
    for (int k = 0; k < 8; k++) tail[total - 1 - k] = (uint8_t)(bits >> (8 * k));
    sha256_block(h, tail);
    if (total == 128) sha256_block(h, tail + 64);

    for (int k = 0; k < 8; k++) {
        out[4*k]   = (uint8_t)(h[k] >> 24);
        out[4*k+1] = (uint8_t)(h[k] >> 16);
        out[4*k+2] = (uint8_t)(h[k] >> 8);
        out[4*k+3] = (uint8_t)(h[k]);
    }
}
