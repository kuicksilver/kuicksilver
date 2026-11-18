/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Checks that every file of a ksl.parsers corpus directory is named by the FNV-1a 64 of its bytes (fnv.h), as the driver
   names the inputs it keeps; with --rename, renames each misnamed one to that name instead (refusing a name another file
   holds: the same bytes twice, left for the caller to resolve). The hash is checked against its reference values first,
   so a wrong constant fails here before it can name anything. Run by tools/c-test.sh before the corpus replay.
   Usage: corpus-names [--rename] DIR...   (exit 1 on a misnamed file or a failed reference value, 2 on an error) */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

/* A rename --rename could not do at once: [entry] (now at [from]) wants [name], held by another file. */
typedef struct { char from[4096], entry[256], name[17]; int done; } pending;

static int by_name(const void *x, const void *y) { return strcmp(*(char *const *)x, *(char *const *)y); }

int main(int argc, char **argv) {
    int rename_them = 0, first = 1, bad = 0, renamed = 0, files = 0;
    if (argc > 1 && !strcmp(argv[1], "--rename")) { rename_them = 1; first = 2; }
    if (first >= argc) { fprintf(stderr, "usage: corpus-names [--rename] DIR...\n"); return 2; }
    if (reference_values()) return 1;
    for (int a = first; a < argc; a++) {
        /* the names first, then the checks and renames: renaming while readdir iterates may skip or repeat entries */
        DIR *dir = opendir(argv[a]);
        if (!dir) { fprintf(stderr, "corpus-names: %s: %s\n", argv[a], strerror(errno)); return 2; }
        char **names = NULL;
        size_t count = 0, cap = 0;
        pending *pend = NULL;
        size_t npend = 0, cappend = 0;
        struct dirent *e;
        while ((e = readdir(dir))) {
            if (e->d_name[0] == '.') continue;
            if (count == cap) {
                cap = cap ? 2 * cap : 64;
                char **grown = realloc(names, cap * sizeof *names);
                if (!grown) { fprintf(stderr, "corpus-names: out of memory\n"); return 2; }
                names = grown;
            }
            if (!(names[count++] = strdup(e->d_name))) { fprintf(stderr, "corpus-names: out of memory\n"); return 2; }
        }
        closedir(dir);
        qsort(names, count, sizeof *names, by_name);
        for (size_t k = 0; k < count; k++) {
            const char *entry = names[k];
            char path[4096], name[17], to[4096];
            snprintf(path, sizeof path, "%s/%s", argv[a], entry);
            struct stat st;
            if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) { fprintf(stderr, "corpus-names: %s is no regular file\n", path); bad = 1; continue; }
            FILE *f = fopen(path, "rb");
            if (!f) { fprintf(stderr, "corpus-names: %s: %s\n", path, strerror(errno)); return 2; }
            uint8_t *buf = malloc(st.st_size ? (size_t)st.st_size : 1);
            size_t n = buf ? fread(buf, 1, (size_t)st.st_size, f) : 0;
            fclose(f);
            if (!buf || n != (size_t)st.st_size) { fprintf(stderr, "corpus-names: %s: short read\n", path); free(buf); return 2; }
            snprintf(name, sizeof name, "%016llx", (unsigned long long)ksl_fnv1a64(buf, n));
            free(buf);
            files++;
            if (!strcmp(entry, name)) continue;
            snprintf(to, sizeof to, "%s/%s", argv[a], name);
            if (!rename_them) { printf("%s: named %s, but the FNV-1a 64 of its bytes is %s\n", path, entry, name); bad = 1; continue; }
            if (lstat(to, &st) == 0) {
                int same = same_bytes(path, to);
                if (same < 0) { fprintf(stderr, "corpus-names: %s or %s: %s\n", path, to, strerror(errno)); return 2; }
                if (same) { printf("%s: its name %s is taken by the same bytes (a duplicate)\n", path, name); bad = 1; continue; }
                /* held by another input, maybe a misnamed one renamed later in this run: the next pass */
                if (npend == cappend) {
                    cappend = cappend ? 2 * cappend : 16;
                    pending *grown = realloc(pend, cappend * sizeof *pend);
                    if (!grown) { fprintf(stderr, "corpus-names: out of memory\n"); return 2; }
                    pend = grown;
                }
                pending *q = &pend[npend++];
                snprintf(q->from, sizeof q->from, "%s", path);
                snprintf(q->entry, sizeof q->entry, "%s", entry);
                memcpy(q->name, name, sizeof q->name);
                q->done = 0;
                continue;
            }
            if (rename(path, to) != 0) { fprintf(stderr, "corpus-names: %s -> %s: %s\n", path, to, strerror(errno)); return 2; }
            printf("%s -> %s\n", entry, name);
            renamed++;
        }
        /* the refused renames, pass after pass, while one makes progress: a chain (A wants B's name, B wants C's) resolves
           from its end; a cycle (A wants B's name, B wants A's) is broken by moving one of its files to a temporary name;
           a name held by an input that keeps it (other bytes with the same FNV-1a 64) is reported */
        for (int tmp = 0;;) {
            int progress = 0, left = 0;
            for (size_t k = 0; k < npend; k++) {
                pending *q = &pend[k];
                if (q->done) continue;
                char to[4096];
                snprintf(to, sizeof to, "%s/%s", argv[a], q->name);
                struct stat st;
                if (lstat(to, &st) == 0) {
                    int same = same_bytes(q->from, to);
                    if (same < 0) { fprintf(stderr, "corpus-names: %s or %s: %s\n", q->from, to, strerror(errno)); return 2; }
                    if (same) { printf("%s/%s: its name %s is taken by the same bytes (a duplicate)\n", argv[a], q->entry, q->name); bad = 1; q->done = 1; progress = 1; }
                    else left++;
                    continue;
                }
                if (rename(q->from, to) != 0) { fprintf(stderr, "corpus-names: %s -> %s: %s\n", q->from, to, strerror(errno)); return 2; }
                printf("%s -> %s\n", q->entry, q->name);
                renamed++;
                q->done = 1;
                progress = 1;
            }
            if (!left) break;
            if (progress) continue;
            /* no progress: a holder still pending is part of a cycle; move the first such pending file out of the way */
            int moved = 0;
            for (size_t k = 0; k < npend && !moved; k++) {
                pending *q = &pend[k];
                if (q->done) continue;
                for (size_t h = 0; h < npend; h++) {
                    if (h == k || pend[h].done) continue;
                    char held[4096];
                    snprintf(held, sizeof held, "%s/%s", argv[a], q->name);
                    if (strcmp(pend[h].from, held) != 0) continue;
                    char aside[4096];
                    snprintf(aside, sizeof aside, "%s/.corpus-names-%d", argv[a], tmp++);
                    if (rename(pend[h].from, aside) != 0) { fprintf(stderr, "corpus-names: %s -> %s: %s\n", pend[h].from, aside, strerror(errno)); return 2; }
                    snprintf(pend[h].from, sizeof pend[h].from, "%s", aside);
                    moved = 1;
                    break;
                }
            }
            if (moved) continue;
            for (size_t k = 0; k < npend; k++) {
                if (pend[k].done) continue;
                printf("%s/%s: its name %s is held by another input with other bytes\n", argv[a], pend[k].entry, pend[k].name);
                bad = 1;
                char back[4096];
                snprintf(back, sizeof back, "%s/%s", argv[a], pend[k].entry);
                if (strcmp(back, pend[k].from) != 0 && rename(pend[k].from, back) != 0) {   /* moved aside: back where it was */
                    fprintf(stderr, "corpus-names: %s -> %s: %s\n", pend[k].from, back, strerror(errno));
                    return 2;
                }
            }
            break;
        }
        free(pend);
        for (size_t k = 0; k < count; k++) free(names[k]);
        free(names);
    }
    fprintf(stderr, "corpus-names: %d file(s), %d renamed, %s\n", files, renamed, bad ? "misnamed ones left" : "every name is its bytes' FNV-1a 64");
    return bad;
}
