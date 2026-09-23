
#ifndef MEDREC_COMMON_H
#define MEDREC_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define APP_DIR      "/srv/medrec"
#define DB_PATH      "data/users.db"
#define ARCHIVE_DIR  "data/archive"
#define REND_SOCK    "/run/medrec/rend.sock"

#define FRONT_UID 1001
#define FRONT_GID 1001
#define REND_UID  1002
#define REND_GID  1002

#define TCP_PORT      9999

#define MAX_DOCTORS   2048
#define MAX_PATIENTS  4096
#define MAX_PAT_PER_DOC 16
#define MAX_BODY      4096

#define RECORD_TTL    1800

#define MAX_CHILDREN      256
#define IDLE_TIMEOUT      30

#define MAX_REG_PER_CONN    8
#define MAX_ADMIT_PER_CONN  32

#define MAX_LINE      65536

#define F_SENSITIVE   1u

struct patient {
    uint32_t pid;
    uint32_t owner;
    uint32_t body_len;
    uint32_t flags;
    char     name[32];
    char     body[];
};

#define CHART_PAGE 160

struct doctor {
    struct patient *pat[MAX_PAT_PER_DOC];
    uint32_t n_pat;
    uint32_t idx;
    uint32_t rsv0;
    uint32_t rsv1;
    char     doctor_id[32];
    char     dept[32];
    char     remark[64];
    char     password[64];
};

extern struct doctor  *g_doctors[MAX_DOCTORS];
extern struct patient *g_patients[MAX_PATIENTS];
extern uint32_t        g_n_doctors;
extern uint32_t        g_n_patients;

void            db_load(void);
struct doctor  *db_find_doctor(const char *id);
struct patient *db_find_patient(uint32_t pid);
int             db_add_doctor(const char *id, const char *pw, const char *dept,
                              const uint8_t *remark, size_t rlen);
int             db_add_patient(struct doctor *own, const char *name, uint32_t flags,
                               const uint8_t *body, size_t blen, uint32_t *out_pid);
void            db_log_amend(uint32_t pid, uint32_t off, const uint8_t *data, size_t n);
void            db_log_discharge(uint32_t pid);

#define PAPER_ROWS     8
#define PAPER_COLS     32
#define PRINT_SPOOL    0x420
#define MAX_CELLS      16
#define MAX_FIELD_LEN  0x800
#define AID_LEN        12

struct sheet {
    char     name[16];
    uint32_t rows;
    uint32_t cols;
    uint32_t margin_top;
    uint32_t margin_left;
    char     unit[16];
};

struct cell {
    uint16_t row;
    uint16_t col;
    uint32_t len;
    char    *data;
    uint32_t used;
    uint32_t flags;
};

struct form {
    struct sheet *sheet;
    char         *canvas;
    uint32_t      canvas_sz;
    uint32_t      n_cell;
    struct cell  *cells[MAX_CELLS];
};

struct joblog {
    uint32_t n_preview;
    uint32_t n_archive;
    char     last[32];
};

struct rdbuf {
    int    fd;
    size_t len;
    size_t pos;
    char   buf[8192];
};

void   rb_init(struct rdbuf *rb, int fd);
int    rb_readline(struct rdbuf *rb, char *out, size_t cap);

void   wr(int fd, const void *p, size_t n);
void   wrstr(int fd, const char *s);
void   wrf(int fd, const char *fmt, ...);
void   send_data(int fd, const void *p, size_t n);

size_t hex2bin(const char *hex, uint8_t *out, size_t cap);
void   bin2hex(const uint8_t *in, size_t n, char *out);
int    is_hex(const char *s, size_t want_chars);

void   sha256(const uint8_t *d, size_t n, uint8_t out[32]);
void   rand_hex(char *out, size_t nhex);
int    ct_memcmp(const void *a, const void *b, size_t n);

const char *rend_sock_path(void);
const char *app_dir_path(void);

ssize_t readn(int fd, void *p, size_t n);
ssize_t writen(int fd, const void *p, size_t n);

int    split(char *line, char *tok[], int maxtok);

void front_main(int fd);
void rend_main(int fd);

#endif
