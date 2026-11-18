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
            if (lstat(to, &st) == 0) { printf("%s: its name %s is taken (the same bytes twice)\n", path, name); bad = 1; continue; }
            if (rename(path, to) != 0) { fprintf(stderr, "corpus-names: %s -> %s: %s\n", path, to, strerror(errno)); return 2; }
            printf("%s -> %s\n", entry, name);
            renamed++;
        }
        for (size_t k = 0; k < count; k++) free(names[k]);
        free(names);
    }
    fprintf(stderr, "corpus-names: %d file(s), %d renamed, %s\n", files, renamed, bad ? "misnamed ones left" : "every name is its bytes' FNV-1a 64");
    return bad;
}
