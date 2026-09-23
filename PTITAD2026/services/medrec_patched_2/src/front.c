
#define _GNU_SOURCE
#include "common.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const char HELP_FRONT[] =
"# MedRec EHR v3.2\n"
"#   REGISTER  <doctor_id> <password> <dept> <remark_hex>\n"
"#   LOGIN     <doctor_id> <password>\n"
"#   WHOAMI\n"
"#   STAFF     <idx> <len>\n"
"#   ROSTER    <dept>\n"
"#   PATIENTS  <doctor_id>\n"
"#   ADMIT     <name> <SENS|NORM> <diagnosis_hex>\n"
"#   CHART     <pid> <off> <len>\n"
"#   EXPORT    <pid> <off>\n"
"#   AMEND     <pid> <off> <data_hex>\n"
"#   DISCHARGE <pid>\n"
"#   FORM BEGIN\n"
"#   HELP\n"
"#   QUIT\n"
"OK HELP\n";

static struct rdbuf   RB;
static struct doctor *g_cur;
static int            g_reg_cnt;
static int            g_admit_cnt;

static void dump_staff_card(int fd, struct doctor *d, int len)
{
    if (len < 0) len = 0;
    if (len > 128) len = 128;

    wrf(fd, "OK ID=%.31s DEPT=%.31s\n", d->doctor_id, d->dept);

    /*
     * Checker-compatible fix for the original 128-byte STAFF/ROSTER
     * response shape: return the requested length, but never read past
     * the 64-byte public remark. The remaining bytes are zero padding,
     * not the adjacent password field.
     */
    uint8_t safe[128];
    memset(safe, 0, sizeof safe);
    memcpy(safe, d->remark, sizeof d->remark);
    send_data(fd, safe, (size_t)len);
}

static void cmd_staff(int fd, int idx, int len)
{
    if (idx < 0 || (uint32_t)idx >= g_n_doctors) {
        wrstr(fd, "ERR NO_SUCH_STAFF\n");
        return;
    }
    dump_staff_card(fd, g_doctors[idx], len);
}

static void cmd_roster(int fd, const char *dept)
{
    char key[32];
    memset(key, 0, sizeof key);
    strncpy(key, dept, sizeof key - 1);

    int found = 0;
    for (uint32_t i = 0; i < g_n_doctors; i++) {
        if (memcmp(g_doctors[i]->dept, key, 32) != 0) continue;
        wrf(fd, "OK IDX %u\n", i);
        dump_staff_card(fd, g_doctors[i], 128);
        found++;
    }
    wrf(fd, "OK ROSTER %d\n", found);
}

static void cmd_patients(int fd, const char *doctor_id)
{
    struct doctor *d = db_find_doctor(doctor_id);
    if (!d) {
        wrstr(fd, "ERR NO_SUCH_STAFF\n");
        return;
    }
    uint32_t n = 0;
    for (uint32_t i = 0; i < d->n_pat; i++) {
        struct patient *p = d->pat[i];
        if (!p) continue;

        char nm[33];
        memset(nm, 0, sizeof nm);
        memcpy(nm, p->name, 32);
        char hex[2 * 32 + 1];
        bin2hex((const uint8_t *)nm, strnlen(nm, 32), hex);

        wrf(fd, "OK PATIENT %u %s %u %s\n", p->pid,
            (p->flags & F_SENSITIVE) ? "SENS" : "NORM", p->body_len,
            hex[0] ? hex : "-");
        n++;
    }
    wrf(fd, "OK PATIENTS %u\n", n);
}

static void chart_page(int fd, struct patient *p, int off, int len)
{
    if (off < 0 || (uint32_t)off > p->body_len) {
        wrstr(fd, "ERR RANGE\n");
        return;
    }

    if (len < 0 || len > CHART_PAGE) len = CHART_PAGE;

    /* Clamp reads to the remaining patient body to prevent heap OOB leaks. */
    size_t avail = (size_t)p->body_len - (size_t)off;
    if ((size_t)len > avail) len = (int)avail;

    send_data(fd, p->body + off, (size_t)len);
}

static struct patient *chart_open(int fd, int pid)
{
    struct patient *p = db_find_patient((uint32_t)pid);
    if (!p) {
        wrstr(fd, "ERR NO_SUCH_PATIENT\n");
        return NULL;
    }
    if ((p->flags & F_SENSITIVE) && (!g_cur || p->owner != g_cur->idx)) {
        wrstr(fd, "ERR ACCESS_DENIED\n");
        return NULL;
    }
    return p;
}

static void cmd_chart(int fd, int pid, int off, int len)
{
    struct patient *p = chart_open(fd, pid);
    if (p) chart_page(fd, p, off, len);
}

static void cmd_export(int fd, int pid, int off)
{
    struct patient *p = chart_open(fd, pid);
    if (p) chart_page(fd, p, off, CHART_PAGE);
}

static void cmd_amend(int fd, int pid, int off, const uint8_t *data, size_t n)
{
    struct patient *p = db_find_patient((uint32_t)pid);
    if (!p) {
        wrstr(fd, "ERR NO_SUCH_PATIENT\n");
        return;
    }
    if (!g_cur || p->owner != g_cur->idx) {
        wrstr(fd, "ERR ACCESS_DENIED\n");
        return;
    }

    if (off < 0 || n > (size_t)p->body_len || (size_t)off > (size_t)p->body_len - n) {
        wrstr(fd, "ERR RANGE\n");
        return;
    }
    memcpy(p->body + off, data, n);
    db_log_amend(p->pid, (uint32_t)off, data, n);
    wrstr(fd, "OK AMENDED\n");
}

static void cmd_discharge(int fd, int pid)
{
    struct patient *p = db_find_patient((uint32_t)pid);
    if (!p) {
        wrstr(fd, "ERR NO_SUCH_PATIENT\n");
        return;
    }
    if (!g_cur || p->owner != g_cur->idx) {
        wrstr(fd, "ERR ACCESS_DENIED\n");
        return;
    }
    uint32_t pidv = p->pid;
    for (uint32_t k = 0; k < g_cur->n_pat; k++)
        if (g_cur->pat[k] == p) g_cur->pat[k] = NULL;
    for (uint32_t i = 0; i < g_n_patients; i++)
        if (g_patients[i] == p) g_patients[i] = NULL;

    explicit_bzero(p, sizeof *p + p->body_len);
    free(p);

    db_log_discharge(pidv);
    wrstr(fd, "OK DISCHARGED\n");
}

static int rend_connect(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, rend_sock_path(), sizeof a.sun_path - 1);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static void form_relay(int cfd, int rfd)
{
    if (RB.pos < RB.len) {
        wr(rfd, RB.buf + RB.pos, RB.len - RB.pos);
        RB.pos = RB.len;
    }
    char buf[4096];
    for (;;) {
        struct pollfd p[2];
        p[0].fd = cfd; p[0].events = POLLIN; p[0].revents = 0;
        p[1].fd = rfd; p[1].events = POLLIN; p[1].revents = 0;
        if (poll(p, 2, IDLE_TIMEOUT * 1000) <= 0) break;

        int dead = 0;
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t k = read(cfd, buf, sizeof buf);
            if (k <= 0) dead = 1; else wr(rfd, buf, (size_t)k);
        }
        if (!dead && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t k = read(rfd, buf, sizeof buf);
            if (k <= 0) dead = 1; else wr(cfd, buf, (size_t)k);
        }

        explicit_bzero(buf, sizeof buf);
        if (dead) break;
    }
    close(rfd);
}

void front_main(int fd)
{
    char  line[MAX_LINE];
    char *tok[8];

    rb_init(&RB, fd);
    db_load();

    wrstr(fd, "=== MedRec EHR v3.2 ===\n");
    wrstr(fd, "OK READY (type HELP)\n");

    while (rb_readline(&RB, line, sizeof line) >= 0) {
        int n = split(line, tok, 8);
        if (n == 0) continue;

        if (!strcmp(tok[0], "HELP")) {
            wrstr(fd, HELP_FRONT);
            continue;
        }

        if (!strcmp(tok[0], "QUIT")) {
            wrstr(fd, "OK BYE\n");
            return;
        }

        if (!strcmp(tok[0], "REGISTER")) {
            if (n < 5) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (g_reg_cnt >= MAX_REG_PER_CONN) { wrstr(fd, "ERR TOO_MANY\n"); continue; }
            if (strlen(tok[1]) > 31 || strlen(tok[2]) > 63 || strlen(tok[3]) > 31) {
                wrstr(fd, "ERR TOO_LONG\n"); continue;
            }
            uint8_t rem[64];
            memset(rem, 0, sizeof rem);
            size_t rl = hex2bin(tok[4], rem, sizeof rem);
            int r = db_add_doctor(tok[1], tok[2], tok[3], rem, rl);
            if (r == -2)      wrstr(fd, "ERR EXISTS\n");
            else if (r < 0)   wrstr(fd, "ERR FULL\n");
            else { g_reg_cnt++; wrf(fd, "OK IDX %d\n", r); }
            continue;
        }

        if (!strcmp(tok[0], "LOGIN")) {
            if (n < 3) { wrstr(fd, "ERR USAGE\n"); continue; }
            struct doctor *d = db_find_doctor(tok[1]);
            if (!d) { wrstr(fd, "ERR BAD_CRED\n"); continue; }
            char pw[64];
            memset(pw, 0, sizeof pw);
            strncpy(pw, tok[2], sizeof pw - 1);
            if (ct_memcmp(pw, d->password, 64) != 0) { wrstr(fd, "ERR BAD_CRED\n"); continue; }
            g_cur = d;
            wrf(fd, "OK LOGIN %u\n", d->idx);
            continue;
        }

        if (!strcmp(tok[0], "WHOAMI")) {
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            wrf(fd, "OK %.31s %u\n", g_cur->doctor_id, g_cur->idx);
            continue;
        }

        if (!strcmp(tok[0], "STAFF")) {
            if (n < 3) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            cmd_staff(fd, atoi(tok[1]), atoi(tok[2]));
            continue;
        }

        if (!strcmp(tok[0], "ROSTER")) {
            if (n < 2) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            cmd_roster(fd, tok[1]);
            continue;
        }

        if (!strcmp(tok[0], "PATIENTS")) {
            if (n < 2) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            cmd_patients(fd, tok[1]);
            continue;
        }

        if (!strcmp(tok[0], "ADMIT")) {
            if (n < 4) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            if (g_admit_cnt >= MAX_ADMIT_PER_CONN) { wrstr(fd, "ERR TOO_MANY\n"); continue; }
            uint32_t flags = strcmp(tok[2], "SENS") == 0 ? F_SENSITIVE : 0;
            static uint8_t body[MAX_BODY];
            size_t bl = hex2bin(tok[3], body, sizeof body);
            if (bl == 0) { wrstr(fd, "ERR BAD_HEX\n"); continue; }
            uint32_t pid = 0;
            int r = db_add_patient(g_cur, tok[1], flags, body, bl, &pid);
            if (r != 0) { wrstr(fd, "ERR FULL\n"); continue; }
            g_admit_cnt++;
            wrf(fd, "OK PID %u\n", pid);
            continue;
        }

        if (!strcmp(tok[0], "CHART")) {
            if (n < 4) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            cmd_chart(fd, (int)strtoul(tok[1], NULL, 10), atoi(tok[2]), atoi(tok[3]));
            continue;
        }

        if (!strcmp(tok[0], "EXPORT")) {
            if (n < 3) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            cmd_export(fd, (int)strtoul(tok[1], NULL, 10), atoi(tok[2]));
            continue;
        }

        if (!strcmp(tok[0], "AMEND")) {
            if (n < 4) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            static uint8_t buf[MAX_BODY];
            size_t bl = hex2bin(tok[3], buf, sizeof buf);
            if (bl == 0) { wrstr(fd, "ERR BAD_HEX\n"); continue; }
            cmd_amend(fd, (int)strtoul(tok[1], NULL, 10), atoi(tok[2]), buf, bl);
            continue;
        }

        if (!strcmp(tok[0], "DISCHARGE")) {
            if (n < 2) { wrstr(fd, "ERR USAGE\n"); continue; }
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            cmd_discharge(fd, (int)strtoul(tok[1], NULL, 10));
            continue;
        }

        if (!strcmp(tok[0], "FORM") && n >= 2 && !strcmp(tok[1], "BEGIN")) {
            if (!g_cur) { wrstr(fd, "ERR NO_AUTH\n"); continue; }
            int rfd = rend_connect();
            if (rfd < 0) { wrstr(fd, "ERR RENDER_DOWN\n"); continue; }
            wrstr(fd, "OK FORM\n");
            form_relay(fd, rfd);
            return;
        }

        wrstr(fd, "ERR UNKNOWN\n");
    }
}
