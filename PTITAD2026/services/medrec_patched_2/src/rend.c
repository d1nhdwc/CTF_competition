
#define _GNU_SOURCE
#include "common.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const struct sheet SHEETS[] = {
    { "A5",      8, 32, 1, 1, "mm" },
    { "A4",     12, 48, 2, 2, "mm" },
    { "LETTER", 12, 44, 2, 2, "in" },
};
#define N_SHEETS ((int)(sizeof(SHEETS) / sizeof(SHEETS[0])))

static const char HELP_REND[] =
"# MedRec form renderer 2014.3\n"
"#   SHEET     <A5|A4|LETTER>\n"
"#   FIELD ADD <row> <col> <len>\n"
"#   FIELD SET <fid> <data_hex>\n"
"#   FIELD GET <fid>\n"
"#   FIELD DEL <fid>\n"
"#   STAMP     <row> <col> <data_hex>\n"
"#   PREVIEW\n"
"#   ARCHIVE   <data_hex>\n"
"#   VERIFY    <archive_id> <sha256_hex>\n"
"#   HELP\n"
"#   END\n"
"OK HELP\n";

static struct rdbuf    RB;
static struct form    *g_form;
static struct joblog  *g_log;

#ifdef DEV_MODE

static void dbg(const char *tag, const void *p)
{
    const char *f = getenv("MEDREC_DBG");
    if (!f) return;
    int d = open(f, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (d < 0) return;
    char b[128];
    int  n = snprintf(b, sizeof b, "%-12s %p\n", tag, p);
    if (n > 0) writen(d, b, (size_t)n);
    close(d);
}
#else
#define dbg(t, p) ((void)0)
#endif

static const struct sheet *lookup_sheet(const char *name)
{
    for (int i = 0; i < N_SHEETS; i++)
        if (strcmp(SHEETS[i].name, name) == 0) return &SHEETS[i];
    return NULL;
}

static char *spool_new(void)
{
    char *s = malloc(PRINT_SPOOL);
    if (!g_log)
        g_log = calloc(1, sizeof *g_log);
    return s;
}

static struct form *form_new(void)
{
    struct form *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->sheet = malloc(sizeof(struct sheet));
    if (!f->sheet) { free(f); return NULL; }
    memcpy(f->sheet, &SHEETS[0], sizeof(struct sheet));
    f->canvas_sz = SHEETS[0].rows * SHEETS[0].cols;
    f->canvas    = calloc(1, f->canvas_sz);
    if (!f->canvas) { free(f->sheet); free(f); return NULL; }
    memset(f->canvas, ' ', f->canvas_sz);
    dbg("form", f); dbg("sheet", f->sheet); dbg("canvas", f->canvas);
    return f;
}

static void cmd_sheet(int fd, struct form *f, const char *name)
{
    const struct sheet *sd = lookup_sheet(name);
    if (!sd) {
        wrstr(fd, "ERR UNKNOWN_SHEET\n");
        return;
    }

    struct sheet *new_sheet = malloc(sizeof *new_sheet);
    if (!new_sheet) { wrstr(fd, "ERR NOMEM\n"); return; }
    memcpy(new_sheet, sd, sizeof *new_sheet);

    uint32_t new_canvas_sz = sd->rows * sd->cols;
    char *new_canvas = calloc(1, new_canvas_sz);
    if (!new_canvas) {
        free(new_sheet);
        wrstr(fd, "ERR NOMEM\n");
        return;
    }
    memset(new_canvas, ' ', new_canvas_sz);

    free(f->sheet);
    free(f->canvas);
    f->sheet     = new_sheet;
    f->canvas_sz = new_canvas_sz;
    f->canvas    = new_canvas;

    wrf(fd, "OK SHEET %.15s %ux%u\n", sd->name, sd->rows, sd->cols);
}

static void cmd_field_add(int fd, struct form *f, int row, int col, int len)
{
    if (f->n_cell >= MAX_CELLS)            { wrstr(fd, "ERR FULL\n");  return; }
    if (len <= 0 || len > MAX_FIELD_LEN)   { wrstr(fd, "ERR RANGE\n"); return; }

    /* Zero-fill so FIELD GET after FIELD ADD cannot disclose stale heap data. */
    char *buf = calloc(1, (size_t)len);
    if (!buf)                              { wrstr(fd, "ERR NOMEM\n"); return; }

    struct cell *c = calloc(1, sizeof *c);
    if (!c) { free(buf); wrstr(fd, "ERR NOMEM\n"); return; }

    c->row  = (uint16_t)row;
    c->col  = (uint16_t)col;
    c->len  = (uint32_t)len;
    c->data = buf;
    c->used = (uint32_t)len;

    f->cells[f->n_cell] = c;
    dbg("cell", c); dbg("cell.data", buf);
    wrf(fd, "OK FID %u\n", f->n_cell);
    f->n_cell++;
}

static void cmd_field_set(int fd, struct form *f, int fid, const uint8_t *data, size_t n)
{
    if (fid < 0 || (uint32_t)fid >= f->n_cell || !f->cells[fid]) {
        wrstr(fd, "ERR NO_SUCH_FIELD\n");
        return;
    }
    struct cell *c = f->cells[fid];
    if (n > c->len) n = c->len;
    memcpy(c->data, data, n);
    c->used = (uint32_t)n;
    wrf(fd, "OK SET %zu\n", n);
}

static void cmd_field_get(int fd, struct form *f, int fid)
{
    if (fid < 0 || (uint32_t)fid >= f->n_cell || !f->cells[fid]) {
        wrstr(fd, "ERR NO_SUCH_FIELD\n");
        return;
    }
    struct cell *c = f->cells[fid];
    send_data(fd, c->data, c->used);
}

static void cmd_field_del(int fd, struct form *f, int fid)
{
    if (fid < 0 || (uint32_t)fid >= f->n_cell || !f->cells[fid]) {
        wrstr(fd, "ERR NO_SUCH_FIELD\n");
        return;
    }
    struct cell *c = f->cells[fid];
    free(c->data);
    free(c);
    f->cells[fid] = NULL;
    wrstr(fd, "OK DEL\n");
}

static void cmd_stamp(int fd, struct form *f, int row, int col, const uint8_t *text, size_t n)
{
    if (!f->canvas || !f->sheet) { wrstr(fd, "ERR NO_SHEET\n"); return; }
    if (row < 0 || col < 0)      { wrstr(fd, "ERR RANGE\n");    return; }

    if ((uint32_t)row >= f->sheet->rows || (uint32_t)col >= f->sheet->cols) {
        wrstr(fd, "ERR OUT_OF_PAPER\n");
        return;
    }
    size_t off = (size_t)row * f->sheet->cols + (size_t)col;
    if (off > (size_t)f->canvas_sz || n > (size_t)f->canvas_sz - off) {
        wrstr(fd, "ERR RANGE\n");
        return;
    }
    memcpy(f->canvas + off, text, n);
    wrf(fd, "OK STAMP %zu\n", n);
}

static void cmd_preview(int fd, struct form *f)
{
    if (!f->canvas) { wrstr(fd, "ERR NO_SHEET\n"); return; }

    char *spool = spool_new();
    if (!spool) { wrstr(fd, "ERR NOMEM\n"); return; }
    dbg("spool", spool); dbg("joblog", g_log);

    size_t n = 0;
    for (int r = 0; r < PAPER_ROWS; r++) {
        memcpy(spool + n, f->canvas + (size_t)r * PAPER_COLS, PAPER_COLS);
        n += PAPER_COLS;
        spool[n++] = '\n';
    }
    if (g_log) g_log->n_preview++;

    send_data(fd, spool, n);
    explicit_bzero(spool, PRINT_SPOOL);
    free(spool);
}

static int valid_aid(const char *s) { return is_hex(s, AID_LEN); }

static void archive_prune(void)
{
    DIR *d = opendir(ARCHIVE_DIR);
    if (!d) return;
    time_t now = time(NULL);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof path, "%s/%s", ARCHIVE_DIR, e->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && now - st.st_mtime > RECORD_TTL) unlink(path);
    }
    closedir(d);
}

static void cmd_archive(int fd, const char *hex)
{
    char *spool = spool_new();
    if (!spool) { wrstr(fd, "ERR NOMEM\n"); return; }

    size_t n = hex2bin(hex, (uint8_t *)spool, PRINT_SPOOL);
    if (n == 0) {
        explicit_bzero(spool, PRINT_SPOOL);
        free(spool);
        wrstr(fd, "ERR BAD_HEX\n");
        return;
    }

    char aid[AID_LEN + 1];
    char path[512];
    int  afd = -1;
    for (int try = 0; try < 8; try++) {
        rand_hex(aid, AID_LEN);
        snprintf(path, sizeof path, "%s/%s.bin", ARCHIVE_DIR, aid);
        afd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (afd >= 0) break;
    }
    if (afd < 0) {
        explicit_bzero(spool, PRINT_SPOOL);
        free(spool);
        wrstr(fd, "ERR IO\n");
        return;
    }
    writen(afd, spool, n);
    close(afd);

    if (g_log) {
        g_log->n_archive++;
        memcpy(g_log->last, aid, AID_LEN + 1);
    }

    explicit_bzero(spool, PRINT_SPOOL);
    free(spool);

    archive_prune();
    wrf(fd, "OK AID %s\n", aid);
}

static void cmd_verify(int fd, const char *aid, const char *sha_hex)
{
    if (!valid_aid(aid) || !is_hex(sha_hex, 64)) { wrstr(fd, "ERR USAGE\n"); return; }

    uint8_t want[32];
    if (hex2bin(sha_hex, want, sizeof want) != 32) { wrstr(fd, "ERR USAGE\n"); return; }

    char path[512];
    snprintf(path, sizeof path, "%s/%s.bin", ARCHIVE_DIR, aid);
    int afd = open(path, O_RDONLY);
    if (afd < 0) { wrstr(fd, "ERR NO_SUCH_ARCHIVE\n"); return; }

    uint8_t buf[PRINT_SPOOL];
    ssize_t n = readn(afd, buf, sizeof buf);
    close(afd);
    if (n < 0) n = 0;

    uint8_t got[32];
    sha256(buf, (size_t)n, got);
    explicit_bzero(buf, sizeof buf);

    wrstr(fd, ct_memcmp(got, want, 32) == 0 ? "OK MATCH\n" : "OK NOMATCH\n");
}

__attribute__((noinline))
static int rend_handle(int fd, char *line)
{
    char *tok[8];
    int   n = split(line, tok, 8);
    if (n == 0) return 0;

    if (!strcmp(tok[0], "HELP")) { wrstr(fd, HELP_REND); return 0; }

    if (!strcmp(tok[0], "END")) { wrstr(fd, "OK END\n"); return -1; }

    if (!strcmp(tok[0], "SHEET")) {
        if (n < 2) { wrstr(fd, "ERR USAGE\n"); return 0; }
        cmd_sheet(fd, g_form, tok[1]);
        return 0;
    }

    if (!strcmp(tok[0], "FIELD")) {
        if (n < 2) { wrstr(fd, "ERR USAGE\n"); return 0; }
        if (!strcmp(tok[1], "ADD")) {
            if (n < 5) { wrstr(fd, "ERR USAGE\n"); return 0; }
            cmd_field_add(fd, g_form, atoi(tok[2]), atoi(tok[3]), atoi(tok[4]));
        } else if (!strcmp(tok[1], "SET")) {
            if (n < 4) { wrstr(fd, "ERR USAGE\n"); return 0; }
            static uint8_t buf[MAX_FIELD_LEN];
            size_t bl = hex2bin(tok[3], buf, sizeof buf);
            if (bl == 0) { wrstr(fd, "ERR BAD_HEX\n"); return 0; }
            cmd_field_set(fd, g_form, atoi(tok[2]), buf, bl);
        } else if (!strcmp(tok[1], "GET")) {
            if (n < 3) { wrstr(fd, "ERR USAGE\n"); return 0; }
            cmd_field_get(fd, g_form, atoi(tok[2]));
        } else if (!strcmp(tok[1], "DEL")) {
            if (n < 3) { wrstr(fd, "ERR USAGE\n"); return 0; }
            cmd_field_del(fd, g_form, atoi(tok[2]));
        } else {
            wrstr(fd, "ERR USAGE\n");
        }
        return 0;
    }

    if (!strcmp(tok[0], "STAMP")) {
        if (n < 4) { wrstr(fd, "ERR USAGE\n"); return 0; }
        static uint8_t buf[MAX_FIELD_LEN];
        size_t bl = hex2bin(tok[3], buf, sizeof buf);
        if (bl == 0) { wrstr(fd, "ERR BAD_HEX\n"); return 0; }
        cmd_stamp(fd, g_form, atoi(tok[1]), atoi(tok[2]), buf, bl);
        return 0;
    }

    if (!strcmp(tok[0], "PREVIEW")) { cmd_preview(fd, g_form); return 0; }

    if (!strcmp(tok[0], "ARCHIVE")) {
        if (n < 2) { wrstr(fd, "ERR USAGE\n"); return 0; }
        cmd_archive(fd, tok[1]);
        return 0;
    }

    if (!strcmp(tok[0], "VERIFY")) {
        if (n < 3) { wrstr(fd, "ERR USAGE\n"); return 0; }
        cmd_verify(fd, tok[1], tok[2]);
        return 0;
    }

    wrstr(fd, "ERR UNKNOWN\n");
    return 0;
}

void rend_main(int fd)
{
    static char line[MAX_LINE];

    rb_init(&RB, fd);
    g_form = form_new();
    if (!g_form) { wrstr(fd, "ERR NOMEM\n"); return; }

    wrstr(fd, "OK REND 2014.3 (type HELP)\n");

    while (rb_readline(&RB, line, sizeof line) >= 0) {
        if (rend_handle(fd, line) < 0) break;
    }
}
