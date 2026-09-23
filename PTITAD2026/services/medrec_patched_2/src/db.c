
#define _GNU_SOURCE
#include "common.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

struct doctor  *g_doctors[MAX_DOCTORS];
struct patient *g_patients[MAX_PATIENTS];
uint32_t        g_n_doctors;
uint32_t        g_n_patients;

#define EMPTY_DOCTOR_GRACE 10

struct rec_hdr {
    uint8_t  type;
    uint8_t  pad[3];
    uint32_t len;
    uint64_t ts;
};

static void db_append(uint8_t type, const void *p1, size_t n1, const void *p2, size_t n2)
{
    int fd = open(DB_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    flock(fd, LOCK_EX);

    struct rec_hdr h;
    memset(&h, 0, sizeof h);
    h.type = type;
    h.len  = (uint32_t)(n1 + n2);
    h.ts   = (uint64_t)time(NULL);

    writen(fd, &h, sizeof h);
    if (n1) writen(fd, p1, n1);
    if (n2) writen(fd, p2, n2);

    flock(fd, LOCK_UN);
    close(fd);
}

static int doctor_has_patients(uint32_t idx)
{
    for (uint32_t i = 0; i < g_n_patients; i++)
        if (g_patients[i] && g_patients[i]->owner == idx) return 1;
    return 0;
}

static void doctor_remove_at(uint32_t idx)
{
    if (idx >= g_n_doctors || !g_doctors[idx]) return;

    explicit_bzero(g_doctors[idx], sizeof *g_doctors[idx]);
    free(g_doctors[idx]);

    for (uint32_t i = idx + 1; i < g_n_doctors; i++) {
        g_doctors[i - 1] = g_doctors[i];
        if (g_doctors[i - 1]) g_doctors[i - 1]->idx = i - 1;
    }
    g_n_doctors--;
    g_doctors[g_n_doctors] = NULL;

    for (uint32_t i = 0; i < g_n_patients; i++) {
        if (!g_patients[i] || g_patients[i]->owner <= idx) continue;
        g_patients[i]->owner--;
    }
}

static int doctor_evict_empty_oldest(time_t now)
{
    uint32_t victim = MAX_DOCTORS;
    uint32_t oldest = UINT32_MAX;

    for (uint32_t i = 0; i < g_n_doctors; i++) {
        struct doctor *d = g_doctors[i];
        if (!d || d->n_pat || doctor_has_patients(i)) continue;
        if (d->rsv0 && now - (time_t)d->rsv0 < EMPTY_DOCTOR_GRACE) continue;
        if (victim == MAX_DOCTORS || d->rsv0 < oldest) {
            victim = i;
            oldest = d->rsv0;
        }
    }

    if (victim == MAX_DOCTORS) return 0;
    doctor_remove_at(victim);
    return 1;
}

struct doctor *db_find_doctor(const char *id)
{
    char key[32];
    memset(key, 0, sizeof key);
    strncpy(key, id, sizeof key - 1);
    for (uint32_t i = 0; i < g_n_doctors; i++)
        if (memcmp(g_doctors[i]->doctor_id, key, 32) == 0) return g_doctors[i];
    return NULL;
}

struct patient *db_find_patient(uint32_t pid)
{
    for (uint32_t i = 0; i < g_n_patients; i++)
        if (g_patients[i] && g_patients[i]->pid == pid) return g_patients[i];
    return NULL;
}

static void patient_drop(uint32_t pid)
{
    for (uint32_t i = 0; i < g_n_patients; i++) {
        struct patient *p = g_patients[i];
        if (!p || p->pid != pid) continue;
        if (p->owner < g_n_doctors) {
            struct doctor *d = g_doctors[p->owner];
            for (uint32_t k = 0; k < d->n_pat; k++)
                if (d->pat[k] == p) d->pat[k] = NULL;
        }
        explicit_bzero(p, sizeof *p + p->body_len);
        free(p);
        g_patients[i] = NULL;
        return;
    }
}

void db_load(void)
{
    int fd = open(DB_PATH, O_RDONLY);
    if (fd < 0) return;
    flock(fd, LOCK_SH);

    time_t now = time(NULL);

    for (;;) {
        struct rec_hdr h;
        if (readn(fd, &h, sizeof h) != (ssize_t)sizeof h) break;

        int stale = (now - (time_t)h.ts) > RECORD_TTL;

        if (h.type == 'D') {
            uint8_t p[192];
            if (h.len != sizeof p) break;
            if (readn(fd, p, sizeof p) != (ssize_t)sizeof p) break;
            if (stale) continue;
            if (g_n_doctors >= MAX_DOCTORS && !doctor_evict_empty_oldest(now)) continue;

            struct doctor *d = malloc(sizeof *d);
            if (!d) break;
            memset(d, 0, sizeof *d);
            memcpy(d->doctor_id, p,       32);
            memcpy(d->password,  p + 32,  64);
            memcpy(d->dept,      p + 96,  32);
            memcpy(d->remark,    p + 128, 64);
            d->idx = g_n_doctors;
            d->rsv0 = (uint32_t)h.ts;
            g_doctors[g_n_doctors++] = d;

        } else if (h.type == 'P') {
            uint8_t hd[76];
            if (h.len < sizeof hd) break;
            if (readn(fd, hd, sizeof hd) != (ssize_t)sizeof hd) break;
            uint32_t blen;
            memcpy(&blen, hd + 72, 4);
            if (blen > MAX_BODY || h.len != sizeof hd + blen) break;

            char owner_id[33];
            memset(owner_id, 0, sizeof owner_id);
            memcpy(owner_id, hd, 32);

            struct doctor *own = db_find_doctor(owner_id);
            if (stale || !own || g_n_patients >= MAX_PATIENTS ||
                own->n_pat >= MAX_PAT_PER_DOC) {
                if (lseek(fd, blen, SEEK_CUR) < 0) break;
                continue;
            }

            struct patient *pt = malloc(sizeof *pt + blen);
            if (!pt) break;
            memset(pt, 0, sizeof *pt + blen);
            memcpy(&pt->pid,   hd + 32, 4);
            memcpy(&pt->flags, hd + 36, 4);
            memcpy(pt->name,   hd + 40, 32);
            pt->owner    = own->idx;
            pt->body_len = blen;
            if (readn(fd, pt->body, blen) != (ssize_t)blen) { free(pt); break; }
            own->pat[own->n_pat++]   = pt;
            g_patients[g_n_patients++] = pt;

        } else if (h.type == 'A') {
            uint8_t hd[12];
            if (h.len < sizeof hd) break;
            if (readn(fd, hd, sizeof hd) != (ssize_t)sizeof hd) break;
            uint32_t pid, off, n;
            memcpy(&pid, hd, 4); memcpy(&off, hd + 4, 4); memcpy(&n, hd + 8, 4);
            if (n > MAX_BODY || h.len != sizeof hd + n) break;

            uint8_t tmp[MAX_BODY];
            if (readn(fd, tmp, n) != (ssize_t)n) break;
            struct patient *p = db_find_patient(pid);
            if (p && off <= p->body_len && n <= p->body_len - off)
                memcpy(p->body + off, tmp, n);

        } else if (h.type == 'X') {
            uint8_t hd[4];
            if (h.len != sizeof hd) break;
            if (readn(fd, hd, sizeof hd) != (ssize_t)sizeof hd) break;
            uint32_t pid;
            memcpy(&pid, hd, 4);
            patient_drop(pid);

        } else {
            break;
        }
    }

    flock(fd, LOCK_UN);
    close(fd);
}

int db_add_doctor(const char *id, const char *pw, const char *dept,
                  const uint8_t *remark, size_t rlen)
{
    if (g_n_doctors >= MAX_DOCTORS && !doctor_evict_empty_oldest(time(NULL))) return -1;
    if (db_find_doctor(id)) return -2;

    uint8_t p[192];
    memset(p, 0, sizeof p);
    strncpy((char *)p,       id,   31);
    strncpy((char *)p + 32,  pw,   63);
    strncpy((char *)p + 96,  dept, 31);
    if (rlen > 64) rlen = 64;
    memcpy(p + 128, remark, rlen);

    struct doctor *d = malloc(sizeof *d);
    if (!d) return -1;
    memset(d, 0, sizeof *d);
    memcpy(d->doctor_id, p,       32);
    memcpy(d->password,  p + 32,  64);
    memcpy(d->dept,      p + 96,  32);
    memcpy(d->remark,    p + 128, 64);
    d->idx = g_n_doctors;
    d->rsv0 = (uint32_t)time(NULL);
    g_doctors[g_n_doctors++] = d;

    db_append('D', p, sizeof p, NULL, 0);
    return (int)d->idx;
}

int db_add_patient(struct doctor *own, const char *name, uint32_t flags,
                   const uint8_t *body, size_t blen, uint32_t *out_pid)
{
    if (g_n_patients >= MAX_PATIENTS) return -1;
    if (own->n_pat >= MAX_PAT_PER_DOC) return -2;
    if (blen > MAX_BODY) return -3;

    uint32_t pid = 0;
    do {
        char h[9];
        rand_hex(h, 8);
        pid = (uint32_t)strtoul(h, NULL, 16);
    } while (pid == 0 || db_find_patient(pid));

    struct patient *pt = malloc(sizeof *pt + blen);
    if (!pt) return -1;
    memset(pt, 0, sizeof *pt + blen);
    pt->pid      = pid;
    pt->owner    = own->idx;
    pt->flags    = flags;
    pt->body_len = (uint32_t)blen;
    strncpy(pt->name, name, 31);
    memcpy(pt->body, body, blen);

    own->pat[own->n_pat++]     = pt;
    g_patients[g_n_patients++] = pt;

    uint8_t hd[76];
    memset(hd, 0, sizeof hd);
    memcpy(hd, own->doctor_id, 32);
    memcpy(hd + 32, &pid, 4);
    memcpy(hd + 36, &flags, 4);
    strncpy((char *)hd + 40, name, 31);
    uint32_t b32 = (uint32_t)blen;
    memcpy(hd + 72, &b32, 4);
    db_append('P', hd, sizeof hd, body, blen);

    *out_pid = pid;
    return 0;
}

void db_log_amend(uint32_t pid, uint32_t off, const uint8_t *data, size_t n)
{
    uint8_t hd[12];
    uint32_t n32 = (uint32_t)n;
    memcpy(hd, &pid, 4); memcpy(hd + 4, &off, 4); memcpy(hd + 8, &n32, 4);
    db_append('A', hd, sizeof hd, data, n);
}

void db_log_discharge(uint32_t pid)
{
    db_append('X', &pid, 4, NULL, 0);
}
