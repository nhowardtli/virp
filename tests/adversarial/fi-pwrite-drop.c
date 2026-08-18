/*
 * fi-pwrite-drop.c — LD_PRELOAD write-loss shim for the torn-write escalation
 * (adversarial test #3b). See tests/adversarial/MEMO-torn-write-escalation.md.
 *
 * It intercepts pwrite/pwrite64 to a chosen file and, once armed, SILENTLY
 * DROPS matching writes — returning the byte count as if they succeeded, so
 * the caller (SQLite in the daemon) believes the write landed while the bytes
 * never reach the file. This is the userspace analogue of a lying disk /
 * power loss that eats an in-flight write, with DETERMINISTIC control over
 * exactly which bytes vanish (by target file and offset range).
 *
 * ZERO BLAST RADIUS: it is a per-process LD_PRELOAD on the isolated test
 * daemon only. It touches no block device, needs no privilege, and is inert
 * the instant the process exits. It must only ever be pointed at a disposable
 * chain — never the production chain.
 *
 * Config (environment):
 *   FI_DROP_MATCH   substring a target file's path must contain to be eligible
 *                   (e.g. "chain.db-wal" or "chain.db"). Required; empty = off.
 *   FI_DROP_EXCLUDE if set, a path containing this substring is NEVER dropped
 *                   (e.g. MATCH="chain.db" EXCLUDE="-wal" targets the main db
 *                   only, not the write-ahead log).
 *   FI_DROP_TRIGGER path to a trigger file. Dropping is INACTIVE until this
 *                   file exists, then active. Omit = active from the start.
 *   FI_DROP_OFFMIN  drop only writes whose offset >= this (default 0)
 *   FI_DROP_OFFMAX  drop only writes whose offset <= this (default: no upper)
 *   FI_DROP_LOG     append a line per dropped write here (path, off, len)
 *
 * SAFETY: refuses to arm if FI_DROP_MATCH names an absolute production path
 * fragment ("/var/lib/virp" or "/run/virp"); a disposable test path never
 * contains those.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAXFD 4096
static char *fd_path[MAXFD];      /* basename/path recorded at open() */

static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static ssize_t (*real_pwrite64)(int, const void *, size_t, off_t);
static int     (*real_open)(const char *, int, ...);
static int     (*real_open64)(const char *, int, ...);
static int     (*real_openat)(int, const char *, int, ...);

static const char *g_match, *g_exclude, *g_trigger, *g_log;
static off_t g_offmin, g_offmax;   /* g_offmax < 0 => no upper bound */
static bool  g_armed_static;       /* no trigger => armed from start */

__attribute__((constructor))
static void fi_init(void)
{
    real_pwrite   = dlsym(RTLD_NEXT, "pwrite");
    real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
    real_open     = dlsym(RTLD_NEXT, "open");
    real_open64   = dlsym(RTLD_NEXT, "open64");
    real_openat   = dlsym(RTLD_NEXT, "openat");

    g_match   = getenv("FI_DROP_MATCH");
    g_exclude = getenv("FI_DROP_EXCLUDE");
    g_trigger = getenv("FI_DROP_TRIGGER");
    g_log     = getenv("FI_DROP_LOG");
    const char *mn = getenv("FI_DROP_OFFMIN");
    const char *mx = getenv("FI_DROP_OFFMAX");
    g_offmin = mn ? (off_t)strtoll(mn, NULL, 10) : 0;
    g_offmax = mx ? (off_t)strtoll(mx, NULL, 10) : -1;
    g_armed_static = (g_trigger == NULL || g_trigger[0] == '\0');

    if (g_match && (strstr(g_match, "/var/lib/virp") || strstr(g_match, "/run/virp"))) {
        fprintf(stderr, "[fi-pwrite-drop] REFUSING: FI_DROP_MATCH names a "
                        "production path fragment (%s)\n", g_match);
        _exit(97);
    }
}

static void record(int fd, const char *path)
{
    if (fd >= 0 && fd < MAXFD && path) {
        free(fd_path[fd]);
        fd_path[fd] = strdup(path);
    }
}

int open(const char *path, int flags, ...)
{
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, mode_t); va_end(a); }
    int fd = real_open(path, flags, m);
    record(fd, path);
    return fd;
}
int open64(const char *path, int flags, ...)
{
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, mode_t); va_end(a); }
    int fd = real_open64(path, flags, m);
    record(fd, path);
    return fd;
}
int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, mode_t); va_end(a); }
    int fd = real_openat(dirfd, path, flags, m);
    record(fd, path);
    return fd;
}
int close(int fd)
{
    if (fd >= 0 && fd < MAXFD) { free(fd_path[fd]); fd_path[fd] = NULL; }
    int (*real_close)(int) = dlsym(RTLD_NEXT, "close");
    return real_close(fd);
}

static bool should_drop(int fd, off_t off)
{
    if (!g_match || !g_match[0]) return false;
    if (fd < 0 || fd >= MAXFD || !fd_path[fd]) return false;
    if (!strstr(fd_path[fd], g_match)) return false;
    if (g_exclude && g_exclude[0] && strstr(fd_path[fd], g_exclude)) return false;
    if (!g_armed_static) {                    /* trigger-gated */
        struct stat st;
        if (stat(g_trigger, &st) != 0) return false;
    }
    if (off < g_offmin) return false;
    if (g_offmax >= 0 && off > g_offmax) return false;
    return true;
}

static void log_drop(int fd, off_t off, size_t n)
{
    if (!g_log) return;
    FILE *f = fopen(g_log, "a");
    if (!f) return;
    fprintf(f, "DROP path=%s off=%lld len=%zu\n",
            fd_path[fd] ? fd_path[fd] : "?", (long long)off, n);
    fclose(f);
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off)
{
    if (should_drop(fd, off)) { log_drop(fd, off, n); return (ssize_t)n; }
    return real_pwrite(fd, buf, n, off);
}
ssize_t pwrite64(int fd, const void *buf, size_t n, off_t off)
{
    if (should_drop(fd, off)) { log_drop(fd, off, n); return (ssize_t)n; }
    return real_pwrite64(fd, buf, n, off);
}
