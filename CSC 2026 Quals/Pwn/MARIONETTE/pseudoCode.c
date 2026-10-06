/*
 * chall.c — RECONSTRUCTION (không phải source gốc)
 * =================================================
 * Đây là bản mô phỏng *gần tương đương* logic của service `marionette`
 * (PuppetScript VM v1.3.0), dựng lại từ reverse (history.md) + exploit (solve.py).
 *
 * Mục đích: DỄ ĐỌC để hiểu luồng và lỗ hổng. KHÔNG nhằm biên dịch/chạy khớp
 * byte-for-byte với binary gốc. Một số điểm được đơn giản hoá có chủ đích:
 *
 *   - Dispatcher opcode gốc bị OBFUSCATE (permutation theo session + con trỏ
 *     handler XOR-mask, rekey sau mỗi lệnh). Ở đây mình dùng switch/case thẳng
 *     vì giá trị opcode thô vẫn ổn định.
 *   - Seccomp chỉ mô tả ý tưởng (cài filter trước khi chạy bytecode client).
 *   - Một vài hằng số bố cục/giới hạn lấy từ history.md.
 *
 * Các hằng số crypto (A0xx, C1/C2, FNV) và công thức token/key lấy trực tiếp
 * từ solve.py nên phần đó là CHÍNH XÁC về mặt thuật toán.
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ===================================================================== *
 *  1. Hằng số
 * ===================================================================== */

#define C1          0xFF51AFD7ED558CCDULL   /* MurmurHash3 fmix64 */
#define C2          0xC4CEB9FE1A85EC53ULL
#define FNV_PRIME   0x100000001B3ULL
#define FNV_BASIS   0xCBF29CE484223325ULL

/* Vật liệu khoá tĩnh nhúng trong .data (tên theo offset trong binary) */
static const uint64_t A020 = 0xE3A7D1B5924F6C80ULL;
static const uint64_t A028 = 0x9FED4FA8A9104CE8ULL;
static const uint64_t A048 = 0x4F72C3A8B1D5E6F0ULL;
static const uint64_t A058 = 0xECED98D69CC9A698ULL;
static const uint64_t A068 = 0x3C51A7D2E8F61B93ULL;
#define SEED_XOR   (A020 ^ A028)
#define STATIC_G   (A048 ^ A058 ^ A068)

/* Giới hạn VM (history.md §5) */
#define MAX_PROG     4096
#define MAX_RUNS     24
#define INSN_BUDGET  200000
#define STACK_SLOTS  256
#define CALL_SLOTS   64
#define POOL_SLOTS   64            /* số slot object trong pool holder */

/* Giới hạn object */
#define NEWSTR_MAX   144
#define NEWBUF_MAX   512           /* <-- clamp quan trọng: hợp lệ không thể > 512 */
#define OBJ_MAGIC    0x53545050u   /* "PPTS" (little-endian) */

/* Packet types */
enum { PKT_RUN = 1, PKT_POOLINFO = 2, PKT_QUIT = 3, PKT_PRIME = 0x50 };

/* Opcodes (giá trị thô ổn định) */
enum {
    OP_NOP=0x00, OP_PUSH=0x01, OP_POP=0x02, OP_DUP=0x03, OP_SWAP=0x04,
    OP_OVER=0x05, OP_ROT=0x06,
    OP_ADD=0x10, OP_SUB=0x11, OP_MUL=0x12, OP_DIV=0x13, OP_MOD=0x14,
    OP_NEG=0x15, OP_AND=0x16, OP_OR=0x17, OP_XOR=0x18, OP_SHL=0x19,
    OP_SHR=0x1a, OP_NOT=0x1b,
    OP_EQ=0x20, OP_LT=0x21, OP_GT=0x22,
    OP_JMP=0x30, OP_JZ=0x31, OP_JNZ=0x32, OP_CALL=0x33, OP_RET=0x34, OP_HALT=0x35,
    OP_NEWSTR=0x40, OP_NEWBUF=0x41, OP_CLOSURE=0x42, OP_GETSLOT=0x43,
    OP_SETSLOT=0x44, OP_LOADSTR=0x45, OP_STORESTR=0x46, OP_STRLEN=0x47,
    OP_BUFREAD=0x48, OP_BUFWRITE=0x49, OP_OBJTYPE=0x4a,
    OP_PRINTI=0x50, OP_PRINTS=0x51, OP_PRINTH=0x52, OP_RAND=0x53,
    OP_SHUFFLE=0x60, OP_DETACH=0x61, OP_CALLCLO=0x70,
    OP_FLAGDEC=0x66,   /* ẩn: giải mã flag */
    OP_STAGEDOOR=0x99  /* ẩn: ghi flag ra fd 1 (decoy) */
};

/* Kind của object */
enum { KIND_STR = 1, KIND_BUF = 2, KIND_CLOSURE = 3 };

/* ===================================================================== *
 *  2. Object model & VM state
 * ===================================================================== */

/*
 * Bố cục header khớp offset mà exploit dựa vào:
 *   +0x00 magic   +0x04 kind    +0x08 refcount
 *   +0x0c capacity +0x10 length  +0x14 target
 *   +0x18 data
 * `data` được cấp capacity+1 byte (nên NUL-terminator của STORESTR không tràn).
 */
typedef struct Object {
    uint32_t magic;      /* +0x00 "PPTS" */
    uint32_t kind;       /* +0x04 */
    uint32_t refcount;   /* +0x08 */
    uint32_t capacity;   /* +0x0c  <-- MỤC TIÊU corrupt: cần > 512 cho OP_FLAGDEC */
    uint32_t length;     /* +0x10 */
    uint32_t target;     /* +0x14 (closure) */
    uint8_t *data;       /* +0x18 */
} Object;

/*
 * Pool holder: con trỏ `objects` ở +0x08 trỏ tới mảng slot bắt đầu ở +0x18.
 * Đây là mấu chốt của bug SHUFFLE: objects[-2] chính là địa chỉ của chính
 * trường `objects` (holder+0x18 - 16 == holder+0x08).
 */
typedef struct PoolHolder {
    uint64_t  header;               /* +0x00 */
    Object  **objects;              /* +0x08 -> &slots[0] (tức holder+0x18) */
    uint32_t  count;                /* +0x10 số object đã đăng ký */
    uint32_t  _pad;
    Object   *slots[POOL_SLOTS];    /* +0x18 ... */
} PoolHolder;   

typedef struct FlagVault {
    uint8_t  enc[128];     /* flag đã mã hoá, nằm trong trang mmap PROT_NONE */
    uint32_t enc_len;
    uint64_t stream_seed;  /* seed xorshift để tạo keystream */
    uint64_t key_check;    /* kiểm tra trước khi cho giải mã */
    char     prefix[8];    /* <=8 byte trước '{' */
    int      primed;       /* đã nhận đúng packet 0x50 chưa */
} FlagVault;

typedef struct VM {
    uint64_t    stack[STACK_SLOTS];
    int         sp;
    uint32_t    call[CALL_SLOTS];
    int         csp;

    uint64_t    rng;        /* xorshift64 PRNG của VM */
    PoolHolder *pool;
    FlagVault  *vault;      /* trỏ tới trang mmap đã mprotect(PROT_NONE) */

    int         fd;         /* socket client */
    uint64_t    nonce;      /* SESSION NONCE */
    int         runs_left;
} VM;

/* ===================================================================== *
 *  3. Helpers crypto
 * ===================================================================== */

static uint64_t fmix(uint64_t x) {
    x ^= x >> 33;
    x *= C1;
    x ^= x >> 33;
    x *= C2;
    x ^= x >> 33;
    return x;
}

static uint64_t xorshift(uint64_t x) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

static uint64_t fnv1a(const uint8_t *p, size_t n, uint64_t h) {
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= FNV_PRIME;
    }
    return h;
}

/* ===================================================================== *
 *  4. Flag sealing (niêm phong) — chạy MỘT lần mỗi child, trước VM
 * ===================================================================== */

static FlagVault *seal_flag(uint64_t nonce) {
    const char *path = getenv("PUPPET_FLAG");
    if (!path) path = "flag.txt";

    char buf[256] = {0};
    FILE *f = fopen(path, "rb");
    if (!f) exit(1);
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    /* trim whitespace đuôi */
    while (n && (buf[n-1]=='\n'||buf[n-1]=='\r'||buf[n-1]==' '||buf[n-1]=='\t'))
        buf[--n] = 0;

    /* yêu cầu có '{' và ít nhất 1 byte trước nó */
    char *brace = strchr(buf, '{');
    if (!brace || brace == buf) exit(1);

    /* cấp trang riêng rồi khoá lại bằng PROT_NONE */
    FlagVault *v = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    /* giữ tối đa 8 byte prefix trước '{' */
    size_t plen = (size_t)(brace - buf);
    if (plen > 8) plen = 8;
    memcpy(v->prefix, brace - plen, plen);

    /* dẫn xuất keystream seed từ nonce + vật liệu tĩnh + prefix */
    uint64_t pfx_qw = 0;
    memcpy(&pfx_qw, v->prefix, sizeof(pfx_qw) <= 8 ? 8 : 8);
    v->stream_seed = fmix(nonce ^ SEED_XOR) ^ STATIC_G ^ pfx_qw;
    v->key_check   = fmix(v->stream_seed);

    /* mã hoá tối đa 128 byte bằng stream xorshift64 */
    size_t enc_len = n < 128 ? n : 128;
    uint64_t s = v->stream_seed;
    for (size_t i = 0; i < enc_len; i++) {
        s = xorshift(s);
        v->enc[i] = (uint8_t)buf[i] ^ (uint8_t)(s & 0xff);
    }
    v->enc_len = (uint32_t)enc_len;
    v->primed  = 0;

    memset(buf, 0, sizeof(buf));           /* zero plaintext */
    mprotect(v, 4096, PROT_NONE);          /* VM không đọc được nữa */
    return v;
}

/* ===================================================================== *
 *  5. Seccomp (mô tả ý tưởng)
 * ===================================================================== */

static void install_seccomp(void) {
    /*
     * Binary gốc cài một BPF seccomp filter TRƯỚC khi chạy bytecode client,
     * chặn các syscall nguy hiểm (execve, open tùy ý, ...) để không thể chỉ
     * ROP ra shell/đọc file. Vì vậy lời giải phải đi qua logic có sẵn
     * (OP_FLAGDEC) thay vì RCE.
     *
     * (Chi tiết filter lược bỏ ở bản reconstruction này.)
     */
}

/* ===================================================================== *
 *  6. Protocol khung + MAC chain
 * ===================================================================== */

/* Header client->server (big-endian):
 *   [u8 type][u32 seq][u64 mac][u16 len][payload]
 * MAC = FNV1a chain: hash(seq LE32) -> hash(prev_mac LE64) -> hash(payload),
 * khởi tạo từ FNV_BASIS, seq bắt đầu 1 và tăng dần.
 */
typedef struct Proto {
    int      fd;
    uint32_t seq;        /* kỳ vọng kế tiếp */
    uint64_t chain;      /* MAC trước đó */
    uint64_t prev;
} Proto;

static int read_full(int fd, void *p, size_t n) {
    uint8_t *b = p;
    while (n) {
        ssize_t r = read(fd, b, n);
        if (r <= 0) return -1;
        b += r; n -= (size_t)r;
    }
    return 0;
}

/* Trả về type, điền payload/len; -1 nếu lỗi protocol (seq/mac/len sai). */
static int proto_recv(Proto *pr, uint8_t *payload, uint16_t *out_len) {
    uint8_t  type;
    uint32_t seq;
    uint64_t mac;
    uint16_t len;

    if (read_full(pr->fd, &type, 1)) return -1;
    if (read_full(pr->fd, &seq, 4)) return -1;
    if (read_full(pr->fd, &mac, 8)) return -1;
    if (read_full(pr->fd, &len, 2)) return -1;
    seq = ntohl(seq);
    mac = be64toh(mac);
    len = ntohs(len);
    if (len > MAX_PROG + 2) return -1;
    if (len && read_full(pr->fd, payload, len)) return -1;

    if (seq != pr->seq) return -1;         /* sai sequence */

    uint32_t seq_le = htole32(seq);
    uint64_t prev_le = htole64(pr->prev);
    uint64_t want = FNV_BASIS;             /* lưu ý: chain tái khởi mỗi packet */
    want = fnv1a((uint8_t*)&seq_le, 4, want);
    want = fnv1a((uint8_t*)&prev_le, 8, want);
    want = fnv1a(payload, len, want);
    if (mac != want) return -1;            /* sai MAC */

    pr->seq  += 1;
    pr->prev  = want;
    *out_len  = len;
    return type;
}

/* ===================================================================== *
 *  7. Đăng ký object vào pool  (sub_4E30 trong binary)
 * ===================================================================== */

/*
 * Mỗi object mới được ghi vào holder->objects[holder->count++].
 * Bình thường holder->objects == &holder->slots[0]. Nhưng nếu SHUFFLE đã
 * trỏ lệch holder->objects, con trỏ object sẽ bị ghi ra địa chỉ tùy ý.
 */
static void pool_register(PoolHolder *h, Object *obj) {
    h->objects[h->count] = obj;   /* <-- ghi có thể bị chuyển hướng */
    h->count++;
}

static Object *obj_new(VM *vm, uint32_t kind, uint32_t cap) {
    Object *o = calloc(1, sizeof(Object));
    o->magic    = OBJ_MAGIC;
    o->kind     = kind;
    o->refcount = 1;
    o->capacity = cap;
    o->length   = 0;
    o->data     = calloc(1, (size_t)cap + 1);   /* +1 cho NUL */
    pool_register(vm->pool, o);
    return o;
}

static int obj_valid(Object *o) {
    return o && o->magic == OBJ_MAGIC;
}

/* ===================================================================== *
 *  8. SHUFFLE — LỖ HỔNG CHÍNH
 * ===================================================================== */

/*
 * Stack (từ đáy->đỉnh) khi gọi: [ ... , index, value, mode ]
 *   mode 0 = read pool[index] -> đẩy lên stack
 *   mode 1 = write pool[index] = value
 *
 * BUG: nhánh read CHUẨN HOÁ index âm (index += count), nhánh write thì KHÔNG.
 *      => write với index âm ghi NGƯỢC ra trước mảng.
 *      objects[-2] == &holder->objects  => ghi đè chính con trỏ mảng pool.
 */
static void op_shuffle(VM *vm) {
    uint64_t mode  = vm->stack[--vm->sp];
    uint64_t value = vm->stack[--vm->sp];
    int64_t  index = (int64_t)vm->stack[--vm->sp];
    PoolHolder *h = vm->pool;

    if (mode == 0) {
        if (index < 0) index += (int64_t)h->count;
        if (index < 0 || index >= (int64_t)h->count) return;  /* bound check */
        vm->stack[vm->sp++] = (uint64_t)(uintptr_t)h->objects[index];
    } else {
        h->objects[index] = (Object *)(uintptr_t)value;   /* OOB write! */
    }
}

/* ===================================================================== *
 *  9. Packet ẩn 0x50 (priming) & opcode ẩn 0x66 (giải mã flag)
 * ===================================================================== */

/*
 * Token của packet 0x50 phụ thuộc PRNG state SAU init:
 *   seed  = (nonce ^ SEED_XOR) rồi advance qua các lệnh RAND của init
 *   token = fmix( fmix(seed) ^ STATIC_G )
 * (xem vm_seed_after_init/token trong solve.py)
 */
static void handle_prime(VM *vm, const uint8_t *payload, uint16_t len) {
    if (len != 8) return;
    uint64_t got;
    memcpy(&got, payload, 8);

    uint64_t seed  = vm->rng;                       /* state sau init */
    uint64_t token = fmix(fmix(seed) ^ STATIC_G);
    if (got == token) {
        /* mprotect trả lại quyền đọc cho trang flag, đánh dấu primed */
        mprotect(vm->vault, 4096, PROT_READ);
        vm->vault->primed = 1;
    }
}

/*
 * OP_FLAGDEC (0x66): giải mã flag vào buffer đích — chỉ khi:
 *   - đã primed (packet 0x50 đúng),
 *   - key client cung cấp khớp key_check,
 *   - object đích hợp lệ,
 *   - capacity > 512  <-- NEWBUF không thể tạo hợp lệ; phải corrupt qua SHUFFLE.
 */
static void op_flagdec(VM *vm) {
    uint64_t key = vm->stack[--vm->sp];
    Object  *dst = (Object *)(uintptr_t)vm->stack[--vm->sp];

    FlagVault *v = vm->vault;
    if (!v->primed) return;
    if (!obj_valid(dst)) return;
    if (dst->capacity <= 512) return;          /* điều kiện then chốt */

    /* xác thực key: key client == seed ^ v48 ^ STATIC_G ^ prefix_qword
       (ở đây rút gọn thành so khớp key_check đã tính lúc seal) */
    uint64_t pfx_qw = 0;
    memcpy(&pfx_qw, v->prefix, 8);
    uint64_t expect = v->stream_seed ^ fmix(v->key_check) ^ STATIC_G ^ pfx_qw;
    (void)expect;  /* công thức chính xác xem solve.py: key = seed^v48^G^pfx */
    if (fmix(key) != v->key_check) {
        /* cho qua nếu khớp; sai thì bỏ (giản lược) */
    }

    /* giải mã keystream xorshift64 vào dst->data */
    uint64_t s = v->stream_seed;
    uint32_t outn = v->enc_len;
    if (outn > dst->capacity) outn = dst->capacity;
    for (uint32_t i = 0; i < outn; i++) {
        s = xorshift(s);
        dst->data[i] = v->enc[i] ^ (uint8_t)(s & 0xff);
    }
    dst->length = outn;
}

/*
 * OP_STAGEDOOR (0x99): decoy. Nhận immediate LE64, check hash predicate rồi
 * mở lại flag và ghi ra fd 1 (stdout của server process), KHÔNG phải socket
 * client — nên vô dụng khi solve remote.
 */
static void op_stagedoor(VM *vm, uint64_t imm) {
    if (fmix(imm) != fmix(vm->nonce ^ STATIC_G)) return;  /* predicate (giản lược) */
    int fd = open_flag_again();   /* pseudocode */
    char tmp[128];
    ssize_t r = read(fd, tmp, sizeof(tmp));
    if (r > 0) write(1, tmp, (size_t)r);   /* ra stdout server, không ra client */
    close(fd);
}

/* ===================================================================== *
 * 10. In ra client (PRINTS an toàn)
 * ===================================================================== */

static void op_prints(VM *vm) {
    Object *o = (Object *)(uintptr_t)vm->stack[--vm->sp];
    if (!obj_valid(o)) return;
    uint32_t n = o->length;
    if (n > o->capacity) n = o->capacity;    /* clamp an toàn */
    write(vm->fd, o->data, n);
    write(vm->fd, "\n", 1);
}

/* ===================================================================== *
 * 11. Vòng thực thi bytecode (dispatcher GỐC bị obfuscate; đây là bản thẳng)
 * ===================================================================== */

static uint64_t rd_le64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }

static void vm_run(VM *vm, const uint8_t *code, uint16_t clen) {
    size_t pc = 0;
    long budget = INSN_BUDGET;

    while (pc < clen && budget-- > 0) {
        uint8_t op = code[pc++];
        switch (op) {
        case OP_PUSH:
            vm->stack[vm->sp++] = rd_le64(code + pc); pc += 8; break;
        case OP_POP:  vm->sp--; break;
        case OP_DUP:  vm->stack[vm->sp] = vm->stack[vm->sp-1]; vm->sp++; break;
        case OP_SWAP: {
            uint64_t a = vm->stack[vm->sp-1], b = vm->stack[vm->sp-2];
            vm->stack[vm->sp-1] = b; vm->stack[vm->sp-2] = a; break;
        }
        case OP_ADD: { uint64_t b=vm->stack[--vm->sp], a=vm->stack[--vm->sp];
                       vm->stack[vm->sp++] = a + b; break; }
        case OP_SUB: { uint64_t b=vm->stack[--vm->sp], a=vm->stack[--vm->sp];
                       vm->stack[vm->sp++] = a - b; break; }

        case OP_NEWSTR: {  /* [u16 BE len][bytes] inline */
            uint16_t l = ntohs(*(uint16_t*)(code+pc)); pc += 2;
            if (l > NEWSTR_MAX) l = NEWSTR_MAX;
            Object *o = obj_new(vm, KIND_STR, l);
            memcpy(o->data, code+pc, l); o->length = l; pc += l;
            vm->stack[vm->sp++] = (uint64_t)(uintptr_t)o; break;
        }
        case OP_NEWBUF: {  /* [u64 LE cap] clamp 1..512 */
            uint64_t cap = rd_le64(code+pc); pc += 8;
            if (cap < 1) cap = 1;
            if (cap > NEWBUF_MAX) cap = NEWBUF_MAX;    /* <-- clamp */
            Object *o = obj_new(vm, KIND_BUF, (uint32_t)cap);
            vm->stack[vm->sp++] = (uint64_t)(uintptr_t)o; break;
        }

        case OP_SHUFFLE:  op_shuffle(vm); break;
        case OP_FLAGDEC:  op_flagdec(vm); break;
        case OP_PRINTS:   op_prints(vm);  break;
        case OP_STAGEDOOR: {
            uint64_t imm = rd_le64(code+pc); pc += 8;
            op_stagedoor(vm, imm); break;
        }

        case OP_RAND:
            vm->rng = xorshift(vm->rng);
            vm->stack[vm->sp++] = vm->rng; break;

        case OP_HALT: return;

        /* ... các opcode còn lại (MUL/DIV/CMP/JMP/CALL/GETSLOT/SETSLOT/
           LOADSTR/STORESTR/BUFREAD/BUFWRITE/DETACH/CALLCLO...) lược bớt
           cho dễ đọc; cơ chế tương tự. */
        default: break;
        }
    }
}

/* ===================================================================== *
 * 12. Init VM: tạo pool, seed PRNG, chạy init bytecode (dùng RAND nhiều lần)
 * ===================================================================== */

static void vm_init(VM *vm, int fd, uint64_t nonce, FlagVault *vault) {
    memset(vm, 0, sizeof(*vm));
    vm->fd = fd;
    vm->nonce = nonce;
    vm->vault = vault;
    vm->runs_left = MAX_RUNS;

    vm->pool = calloc(1, sizeof(PoolHolder));
    vm->pool->objects = &vm->pool->slots[0];   /* +0x08 trỏ tới +0x18 */
    vm->pool->count   = 0;

    /* PRNG seed ban đầu rồi advance qua init (số lần dẫn xuất từ nonce) */
    vm->rng = nonce ^ SEED_XOR;
    unsigned rc = (unsigned)(fmix(nonce) % 7) + 3;
    rc += (unsigned)(fmix(nonce ^ 0xBEEF) & 3) + 2;
    for (unsigned i = 0; i < rc; i++)
        vm->rng = xorshift(vm->rng);
    /* => vm->rng giờ == vm_seed_after_init(nonce) trong solve.py */
}

/* ===================================================================== *
 * 13. Session handler cho mỗi child
 * ===================================================================== */

static void session(int fd) {
    uint64_t nonce;
    { int u = open("/dev/urandom", 0); read(u, &nonce, 8); close(u); }

    FlagVault *vault = seal_flag(nonce);
    install_seccomp();

    /* banner */
    dprintf(fd,
        "PuppetScript VM v1.3.0\n"
        "Framing client->server, big-endian:\n"
        "[u8 type][u32 seq][u64 mac][u16 len][payload]\n"
        "  type: 1=RUN [u16 proglen][bytecode]  2=POOLINFO  3=QUIT\n"
        "SESSION NONCE %016llx\n"
        "READY\n#OK\n",
        (unsigned long long)nonce);

    VM vm;
    vm_init(&vm, fd, nonce, vault);

    Proto pr = { .fd = fd, .seq = 1, .chain = FNV_BASIS, .prev = 0 };
    uint8_t payload[MAX_PROG + 2];

    for (;;) {
        uint16_t len;
        int type = proto_recv(&pr, payload, &len);
        if (type < 0) { dprintf(fd, "#ERR protocol\n"); return; }

        if (type == PKT_QUIT) return;

        if (type == PKT_POOLINFO) {
            dprintf(fd, "stage %u/%u puppets\n#OK\n",
                    vm.pool->count, POOL_SLOTS);
            continue;
        }

        if (type == PKT_PRIME) {                 /* 0x50 ẩn */
            handle_prime(&vm, payload, len);
            dprintf(fd, "#OK\n");
            continue;
        }

        if (type == PKT_RUN) {
            if (vm.runs_left-- <= 0) { dprintf(fd, "stage full\n#ERR\n"); return; }
            uint16_t proglen = ntohs(*(uint16_t*)payload);
            if (proglen > MAX_PROG || proglen + 2 > len) {
                dprintf(fd, "#ERR protocol\n"); return;
            }
            vm.sp = 0; vm.csp = 0;
            vm_run(&vm, payload + 2, proglen);
            dprintf(fd, "#OK\n");
            continue;
        }

        dprintf(fd, "#ERR protocol\n");
        return;
    }
}

/* ===================================================================== *
 * 14. main: fork server
 * ===================================================================== */

int main(void) {
    const char *ps = getenv("PUPPET_PORT");
    int port = ps ? atoi(ps) : 9999;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    bind(srv, (struct sockaddr*)&sa, sizeof(sa));
    listen(srv, 16);

    for (;;) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) continue;
        pid_t pid = fork();
        if (pid == 0) {                 /* child */
            close(srv);
            /* alarm(PUPPET_TIMEOUT) ... */
            session(cli);
            close(cli);
            _exit(0);
        }
        close(cli);                     /* parent tiếp tục accept */
        while (waitpid(-1, NULL, WNOHANG) > 0) {}
    }
}

/* ===================================================================== *
 *  GHI CHÚ EXPLOIT (tóm tắt, chi tiết xem wu.md / solve.py)
 * ---------------------------------------------------------------------
 *  1. Parse SESSION NONCE; POOLINFO lấy count.
 *  2. Tái tạo vm->rng sau init (vm_seed_after_init).
 *  3. Gửi packet 0x50 với token = fmix(fmix(seed)^STATIC_G) -> primed.
 *  4. Bytecode:
 *       NEWBUF 512                     ; victim (capacity hợp lệ)
 *       DUP ; PUSH 12 ; ADD            ; &victim->capacity (+0x0c)
 *       PUSH 8*(count+1) ; SUB         ; lùi địa chỉ
 *       PUSH -2 ; SWAP ; PUSH 1 ; SHUFFLE  ; holder->objects := addr tùy ý
 *       NEWBUF 1 ; POP                 ; đăng ký -> ghi heap-ptr đè capacity (>512)
 *       DUP ; PUSH key ; OP_FLAGDEC    ; giải mã flag vào victim
 *       PRINTS ; HALT                  ; in flag ra socket
 * ===================================================================== */
