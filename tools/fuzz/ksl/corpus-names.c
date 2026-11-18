/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Checks that every file of a ksl.parsers corpus directory is named by the FNV-1a 64 of its bytes (fnv.h), as the driver
   names the inputs it keeps; with --rename, renames each misnamed one to that name instead. The hash is checked against its
   reference values first, so a wrong constant fails here before it can name anything. Run by tools/c-test.sh before the
   corpus replay, and by tools/fuzz/campaign.sh after a ksl.parsers merge.
   Renaming never overwrites a file: every move is a hard link to a name that must not exist, then the old name's unlink
   (link(2) fails with EEXIST; a file system without hard links gets an O_EXCL copy instead). The misnamed inputs first move
   to visible temporary names (<name>.corpus-names-tmp), then each to its FNV-1a 64 name, so chains and cycles of inputs
   holding each other's names resolve. An input whose name is held by another file stays: back under its old name, or, when
   that is taken meanwhile, under <old name>.unresolved; both are reported and exit 1 (the same bytes twice is a duplicate).
   On an error every move made so far is undone, newest first, before exit 2.
   Usage: corpus-names [--rename] DIR...   (exit 1 on a misnamed or unresolved file or a failed reference value, 2 on an error) */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE /* O_NOFOLLOW, which _POSIX_C_SOURCE hides on macOS */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fnv.h"

static int reference_values(void) {
    static const struct { const char *in; uint64_t want; } kat[] = {
        {"", 0xcbf29ce484222325ull}, {"a", 0xaf63dc4c8601ec8cull}, {"abc", 0xe71fa2190541574bull}};
    int bad = 0;
    for (size_t i = 0; i < sizeof kat / sizeof kat[0]; i++) {
        uint64_t got = ksl_fnv1a64((const uint8_t *)kat[i].in, strlen(kat[i].in));
        if (got != kat[i].want) {
            fprintf(stderr, "corpus-names: FNV-1a 64 of \"%s\" is %016llx, not %016llx\n", kat[i].in, (unsigned long long)got,
                    (unsigned long long)kat[i].want);
            bad = 1;
        }
    }
    return bad;
}

/* Whether the files [x] and [y] hold the same bytes (-1 on an error). */
static int same_bytes(const char *x, const char *y) {
    FILE *f = fopen(x, "rb"), *g = fopen(y, "rb");
    int r = (f && g) ? 1 : -1;
    while (r == 1) {
        int a = fgetc(f), b = fgetc(g);
        if (a != b) r = 0;
        else if (a == EOF) break;
    }
    if (f) fclose(f);
    if (g) fclose(g);
    return r;
}

/* [from] copied to the new file [to] (O_EXCL), for a file system without hard links; 0, or -1 with errno set. */
static int copy_excl(const char *from, const char *to) {
    int in = open(from, O_RDONLY | O_NOFOLLOW);
    if (in < 0) return -1;
    int out = open(to, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (out < 0) { int e = errno; close(in); errno = e; return -1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        for (ssize_t off = 0; off < n;) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0) { int e = errno; close(in); close(out); unlink(to); errno = e ? e : EIO; return -1; }
            off += w;
        }
    }
    int e = n < 0 ? errno : 0;
    close(in);
    if (close(out) != 0 && !e) e = errno;
    if (e) { unlink(to); errno = e; return -1; }
    return 0;
}

/* Moves [from] to [to] only if [to] does not exist; 0, or -1 with errno set (EEXIST: [to] is taken, nothing changed). */
static int move_excl(const char *from, const char *to) {
    if (link(from, to) != 0) {
        if (errno == EEXIST) return -1;
        if (errno != EPERM && errno != ENOTSUP && errno != EOPNOTSUPP && errno != EMLINK) return -1;
        if (copy_excl(from, to) != 0) return -1;
    }
    if (unlink(from) != 0) { int e = errno; unlink(to); errno = e; return -1; }
    return 0;
}

/* The moves made, so that an error can undo them (newest first). */
typedef struct { char from[4096], to[4096]; } move;
static move *moves;
static size_t nmoves, capmoves;

static int record(const char *from, const char *to) {
    if (nmoves == capmoves) {
        capmoves = capmoves ? 2 * capmoves : 64;
        move *grown = realloc(moves, capmoves * sizeof *moves);
        if (!grown) return -1;
        moves = grown;
    }
    snprintf(moves[nmoves].from, sizeof moves[nmoves].from, "%s", from);
    snprintf(moves[nmoves].to, sizeof moves[nmoves].to, "%s", to);
    nmoves++;
    return 0;
}

/* A move that is recorded; on failure nothing moved. */
static int do_move(const char *from, const char *to) {
    if (move_excl(from, to) != 0) return -1;
    if (record(from, to) != 0) { int e = ENOMEM; move_excl(to, from); errno = e; return -1; }
    return 0;
}

/* An error: every move undone, newest first, then exit 2; a move that cannot be undone is named. */
static int fail_hint(const char *what, const char *path, const char *hint) {
    fprintf(stderr, "corpus-names: %s %s: %s\n", what, path, strerror(errno));
    if (hint) fprintf(stderr, "corpus-names: %s\n", hint);
    else if (errno == ENAMETOOLONG) fprintf(stderr, "corpus-names: shorten the input's name (or the directory's path)\n");
    for (size_t i = nmoves; i-- > 0;) {
        if (move_excl(moves[i].to, moves[i].from) != 0) {
            fprintf(stderr, "corpus-names: could not move %s back to %s: %s (the file is still at %s)\n", moves[i].to,
                    moves[i].from, strerror(errno), moves[i].to);
        }
    }
    return 2;
}

static int fail(const char *what, const char *path) { return fail_hint(what, path, NULL); }

/* [dir]/[name][suffix] into [out]; -1 with ENAMETOOLONG when it does not fit (never a cut name). */
static int join(char *out, size_t cap, const char *dir, const char *name, const char *suffix) {
    int n = snprintf(out, cap, "%s/%s%s", dir, name, suffix);
    if (n < 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

typedef struct { char entry[256], tmp[4096], name[17]; } plan;

static int by_name(const void *x, const void *y) { return strcmp(*(char *const *)x, *(char *const *)y); }

int main(int argc, char **argv) {
    int rename_them = 0, first = 1, bad = 0, renamed = 0, files = 0;
    if (argc > 1 && !strcmp(argv[1], "--rename")) { rename_them = 1; first = 2; }
    if (first >= argc) { fprintf(stderr, "usage: corpus-names [--rename] DIR...\n"); return 2; }
    if (reference_values()) return 1;
    for (int a = first; a < argc; a++) {
        /* the names first, then the checks and renames: renaming while readdir iterates may skip or repeat entries */
        DIR *dir = opendir(argv[a]);
        if (!dir) return fail("reading", argv[a]);
        char **names = NULL;
        size_t count = 0, cap = 0;
        struct dirent *e;
        while ((e = readdir(dir))) {
            if (e->d_name[0] == '.') continue;
            if (count == cap) {
                cap = cap ? 2 * cap : 64;
                char **grown = realloc(names, cap * sizeof *names);
                if (!grown) { errno = ENOMEM; closedir(dir); return fail("reading", argv[a]); }
                names = grown;
            }
            if (!(names[count++] = strdup(e->d_name))) { errno = ENOMEM; closedir(dir); return fail("reading", argv[a]); }
        }
        closedir(dir);
        qsort(names, count, sizeof *names, by_name);
        plan *plans = calloc(count ? count : 1, sizeof *plans);
        if (!plans) { errno = ENOMEM; return fail("planning", argv[a]); }
        size_t nplans = 0;
        for (size_t k = 0; k < count; k++) {
            const char *entry = names[k];
            char path[4096], name[17];
            if (join(path, sizeof path, argv[a], entry, "") != 0) return fail("naming", entry);
            struct stat st;
            if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) { fprintf(stderr, "corpus-names: %s is no regular file\n", path); bad = 1; continue; }
            FILE *f = fopen(path, "rb");
            if (!f) return fail("reading", path);
            uint8_t *buf = malloc(st.st_size ? (size_t)st.st_size : 1);
            size_t n = buf ? fread(buf, 1, (size_t)st.st_size, f) : 0;
            fclose(f);
            if (!buf || n != (size_t)st.st_size) { free(buf); errno = buf ? EIO : ENOMEM; return fail("reading", path); }
            snprintf(name, sizeof name, "%016llx", (unsigned long long)ksl_fnv1a64(buf, n));
            free(buf);
            files++;
            if (!strcmp(entry, name)) continue;
            if (!rename_them) { printf("%s: named %s, but the FNV-1a 64 of its bytes is %s\n", path, entry, name); bad = 1; continue; }
            plan *p = &plans[nplans++];
            snprintf(p->entry, sizeof p->entry, "%s", entry);
            memcpy(p->name, name, sizeof p->name);
        }
        /* every misnamed input out of the way first, under a visible name, so the names they held are free */
        for (size_t k = 0; k < nplans; k++) {
            char path[4096];
            if (join(path, sizeof path, argv[a], plans[k].entry, "") != 0 ||
                join(plans[k].tmp, sizeof plans[k].tmp, argv[a], plans[k].entry, ".corpus-names-tmp") != 0)
                return fail("naming", plans[k].entry);
            if (do_move(path, plans[k].tmp) != 0) {
                if (errno != EEXIST) return fail("moving aside", path);
                char hint[4300];
                snprintf(hint, sizeof hint, "remove or rename the stale %s left by an earlier run", plans[k].tmp);
                return fail_hint("moving aside", path, hint);
            }
        }
        /* then each to its name, never over another file, pass after pass while one places an input (a name another of
           them held is free once that one moved on); only then do the rest go back */
        int *placed = calloc(nplans ? nplans : 1, sizeof *placed);
        if (!placed) { errno = ENOMEM; return fail("planning", argv[a]); }
        for (int progress = 1; progress;) {
            progress = 0;
            for (size_t k = 0; k < nplans; k++) {
                plan *p = &plans[k];
                char to[4096];
                if (placed[k]) continue;
                if (join(to, sizeof to, argv[a], p->name, "") != 0) return fail("naming", p->name);
                if (do_move(p->tmp, to) == 0) { printf("%s -> %s\n", p->entry, p->name); renamed++; placed[k] = 1; progress = 1; continue; }
                if (errno != EEXIST) return fail("renaming", p->tmp);
            }
        }
        for (size_t k = 0; k < nplans; k++) {
            plan *p = &plans[k];
            char to[4096], back[4096], aside[4096];
            if (placed[k]) continue;
            if (join(to, sizeof to, argv[a], p->name, "") != 0 || join(back, sizeof back, argv[a], p->entry, "") != 0 ||
                join(aside, sizeof aside, argv[a], p->entry, ".unresolved") != 0)
                return fail("naming", p->entry);
            int same = same_bytes(p->tmp, to);
            if (same < 0) return fail("comparing", to);
            printf("%s/%s: its name %s is taken by %s\n", argv[a], p->entry, p->name, same ? "the same bytes (a duplicate)" : "another input with other bytes");
            bad = 1;
            if (do_move(p->tmp, back) == 0) continue;
            if (errno != EEXIST) return fail("moving back", p->tmp);
            if (do_move(p->tmp, aside) != 0) return fail("moving to .unresolved", p->tmp);
            printf("%s/%s: its old name is taken now too: left as %s\n", argv[a], p->entry, aside);
        }
        free(placed);
        free(plans);
        for (size_t k = 0; k < count; k++) free(names[k]);
        free(names);
        nmoves = 0;   /* this directory is done: an error in the next one does not undo it */
    }
    free(moves);
    fprintf(stderr, "corpus-names: %d file(s), %d renamed, %s\n", files, renamed, bad ? "misnamed ones left" : "every name is its bytes' FNV-1a 64");
    return bad;
}
