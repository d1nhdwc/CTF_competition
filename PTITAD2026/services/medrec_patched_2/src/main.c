
#define _GNU_SOURCE
#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int tcp_listen(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port        = htons((uint16_t)port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) return -1;
    if (listen(s, 64) < 0) return -1;
    return s;
}

static int unix_listen(const char *path)
{
    unlink(path);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, path, sizeof a.sun_path - 1);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) return -1;
    if (chmod(path, 0666) < 0) return -1;
    if (listen(s, 64) < 0) return -1;
    return s;
}

static struct {
    pid_t         pid;
    unsigned long born;
} g_kids[MAX_CHILDREN];

static unsigned long g_seq;

static void reap_children(void)
{
    for (;;) {
        pid_t pid = waitpid(-1, NULL, WNOHANG);
        if (pid <= 0) break;
        for (int i = 0; i < MAX_CHILDREN; i++)
            if (g_kids[i].pid == pid) { g_kids[i].pid = 0; break; }
    }
}

static int kids_total(void)
{
    int n = 0;
    for (int i = 0; i < MAX_CHILDREN; i++)
        if (g_kids[i].pid) n++;
    return n;
}

static void kids_add(pid_t pid)
{
    for (int i = 0; i < MAX_CHILDREN; i++)
        if (!g_kids[i].pid) { g_kids[i].pid = pid; g_kids[i].born = ++g_seq; return; }
}

static void kids_evict_oldest(void)
{
    int oldest = -1;
    for (int i = 0; i < MAX_CHILDREN; i++)
        if (g_kids[i].pid &&
            (oldest < 0 || g_kids[i].born < g_kids[oldest].born)) oldest = i;
    if (oldest < 0) return;
    kill(g_kids[oldest].pid, SIGKILL);
    waitpid(g_kids[oldest].pid, NULL, 0);
    g_kids[oldest].pid = 0;
}

static void drop_to(uid_t uid, gid_t gid)
{
#ifdef DEV_MODE
    if (geteuid() != 0) return;
#endif
    if (setgroups(0, NULL) < 0) _exit(1);
    if (setgid(gid) < 0)        _exit(1);
    if (setuid(uid) < 0)        _exit(1);
    if (getuid() != uid || geteuid() != uid) _exit(1);
    if (setuid(0) == 0)         _exit(1);
}

int main(void)
{
    signal(SIGCHLD, SIG_DFL);
    signal(SIGPIPE, SIG_IGN);

    if (chdir(app_dir_path()) < 0) { perror("chdir"); return 1; }

    int lt = tcp_listen(TCP_PORT);
    int lu = unix_listen(rend_sock_path());
    if (lt < 0 || lu < 0) { perror("listen"); return 1; }

    fprintf(stderr, "[medrecd] up: tcp %d, unix %s\n", TCP_PORT, rend_sock_path());

    for (;;) {
        struct pollfd p[2];
        p[0].fd = lt; p[0].events = POLLIN; p[0].revents = 0;
        p[1].fd = lu; p[1].events = POLLIN; p[1].revents = 0;

        reap_children();

        if (poll(p, 2, 1000) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        reap_children();

        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & POLLIN)) continue;

            int cfd = accept(p[i].fd, NULL, NULL);
            if (cfd < 0) continue;

            while (kids_total() >= MAX_CHILDREN) kids_evict_oldest();

            pid_t pid = fork();
            if (pid == 0) {
                close(lt);
                close(lu);

                struct timeval tv = { IDLE_TIMEOUT, 0 };
                setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

                dup2(cfd, 0);
                dup2(cfd, 1);
                dup2(cfd, 2);
                if (cfd > 2) close(cfd);

                if (i == 0) { drop_to(FRONT_UID, FRONT_GID); front_main(0); }
                else        { drop_to(REND_UID,  REND_GID);  rend_main(0);  }
                _exit(0);
            }
            if (pid > 0) kids_add(pid);
            close(cfd);
        }
    }
    return 0;
}
