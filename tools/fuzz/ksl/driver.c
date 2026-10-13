/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* A small coverage-guided driver for LLVMFuzzerTestOneInput where libFuzzer is not available (Apple clang ships no
   libclang_rt.fuzzer). Coverage comes from -fsanitize-coverage=trace-pc-guard on the harness and ksl (not OpenSSL); an
   input that reaches a new edge joins the corpus (the first directory). Mutations: bit flips, byte sets, interesting
   values, block insert/delete/copy, splicing. ASan/UBSan stop the process on a finding; the death callback writes the
   input to <artifact_prefix>crash-<hash>, a hang past -timeout to timeout-<hash>.
   Flags (libFuzzer's names): -max_total_time=S -runs=N -timeout=S -artifact_prefix=P -merge=1 -seed=N; others ignored.
   With libFuzzer (clang -fsanitize=fuzzer on Linux) build.sh links the harness without this file. */
#include <dirent.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int ksl_fuzz_write_seeds(const char *dir);
void __sanitizer_set_death_callback(void (*callback)(void));

#define MAP (1u << 20)
#define MAX_LEN 16384
static uint32_t guards;
static uint8_t seen[MAP];
static uint32_t touched[MAP], ntouched, covered;
static uint8_t hit[MAP];

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *g = start; g < stop; g++) *g = ++guards % MAP ? guards % MAP : 1;
}
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t g = *guard; if (!g || hit[g]) return;
    hit[g] = 1; touched[ntouched++] = g;
}

typedef struct { uint8_t *d; size_t n; } unit;
static unit *corpus; static size_t ncorpus, capcorpus;
static const uint8_t *cur; static size_t curlen;
static const char *prefix = "";
static char outdir[4096];

static uint64_t fnv(const uint8_t *d, size_t n) { uint64_t h = 1469598103934665603ull; for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= 1099511628211ull; } return h; }
static void save(const char *dir_or_prefix, const char *kind, const uint8_t *d, size_t n, int is_dir) {
    char path[4400];
    if (is_dir) snprintf(path, sizeof path, "%s/%016llx", dir_or_prefix, (unsigned long long)fnv(d, n));
    else snprintf(path, sizeof path, "%s%s-%016llx", dir_or_prefix, kind, (unsigned long long)fnv(d, n));
    FILE *f = fopen(path, "wb"); if (!f) return; fwrite(d, 1, n, f); fclose(f);
    if (!is_dir) fprintf(stderr, "==ksl_fuzz== %s written to %s\n", kind, path);
}
static void on_death(void) { if (cur) save(prefix, "crash", cur, curlen, 0); }
static void on_alarm(int sig) { (void)sig; if (cur) save(prefix, "timeout", cur, curlen, 0); fprintf(stderr, "==ksl_fuzz== timeout\n"); _exit(70); }

static unsigned timeout_s = 60;
/* Runs one input; returns the number of edges it reached for the first time. */
static int run(const uint8_t *d, size_t n) {
    cur = d; curlen = n; ntouched = 0;
    alarm(timeout_s);
    LLVMFuzzerTestOneInput(d, n);
    alarm(0);
    int fresh = 0;
    for (uint32_t i = 0; i < ntouched; i++) { uint32_t g = touched[i]; hit[g] = 0; if (!seen[g]) { seen[g] = 1; fresh++; covered++; } }
    cur = NULL;
    return fresh;
}
static void add(const uint8_t *d, size_t n) {
    if (ncorpus == capcorpus) { capcorpus = capcorpus ? capcorpus * 2 : 256; corpus = realloc(corpus, capcorpus * sizeof *corpus); }
    corpus[ncorpus].d = malloc(n ? n : 1); memcpy(corpus[ncorpus].d, d, n); corpus[ncorpus].n = n; ncorpus++;
}
static void load_dir(const char *dir, int keep_all, int write_new) {
    DIR *dd = opendir(dir); if (!dd) return; struct dirent *e;
    while ((e = readdir(dd))) {
        if (e->d_name[0] == '.') continue;
        char path[4400]; snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        struct stat st; if (stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size > MAX_LEN) continue;
        FILE *f = fopen(path, "rb"); if (!f) continue;
        uint8_t *b = malloc((size_t)st.st_size + 1); size_t n = fread(b, 1, (size_t)st.st_size, f); fclose(f);
        int fresh = run(b, n);
        if (keep_all || fresh) { add(b, n); if (write_new && fresh) save(outdir, "", b, n, 1); }
        free(b);
    }
    closedir(dd);
}

static uint64_t rng = 88172645463325252ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static size_t mutate(uint8_t *b, size_t n, size_t cap) {
    static const int64_t interesting[] = {0, 1, -1, 0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x4000, 0x7fff, 0xffff, 0x10000, 0x7fffffff, 0x3fffffffffffffffll};
    int rounds = 1 + (int)(rnd() % 6);
    for (int r = 0; r < rounds; r++) {
        switch (rnd() % 9) {
        case 0: if (n) b[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;
        case 1: if (n) b[rnd() % n] = (uint8_t)rnd(); break;
        case 2: if (n) { int64_t v = interesting[rnd() % (sizeof interesting / sizeof *interesting)]; size_t w = 1u << (rnd() % 4); size_t p = rnd() % n;
                         for (size_t i = 0; i < w && p + i < n; i++) b[p + i] = (uint8_t)(v >> (8 * (w - 1 - i))); } break;
        case 3: if (n < cap) { size_t p = rnd() % (n + 1), k = 1 + rnd() % 16; if (n + k > cap) k = cap - n; memmove(b + p + k, b + p, n - p);
                               for (size_t i = 0; i < k; i++) b[p + i] = (uint8_t)rnd(); n += k; } break;
        case 4: if (n > 1) { size_t p = rnd() % n, k = 1 + rnd() % (n - p); if (k > 64) k = 64; memmove(b + p, b + p + k, n - p - k); n -= k; } break;
        case 5: if (n > 1) { size_t s = rnd() % n, t = rnd() % n, k = 1 + rnd() % 32; if (s + k > n) k = n - s; if (t + k > n) k = n - t; memmove(b + t, b + s, k); } break;
        case 6: if (ncorpus) { unit *o = &corpus[rnd() % ncorpus]; if (o->n) { size_t s = rnd() % o->n, k = 1 + rnd() % (o->n - s), p = rnd() % (n + 1);
                               if (k > cap - n) k = cap - n; memmove(b + p + k, b + p, n - p); memcpy(b + p, o->d + s, k); n += k; } } break;
        case 7: if (n) { size_t p = rnd() % n; b[p] = (uint8_t)(b[p] + 1 + rnd() % 8); } break;
        default: if (n > 1 && rnd() % 4 == 0) n = 1 + rnd() % n; break;   /* truncate */
        }
    }
    return n;
}

int main(int argc, char **argv) {
    long max_time = 0, runs = -1; int merge = 0; const char *dirs[64]; int ndirs = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strncmp(a, "-max_total_time=", 16)) max_time = atol(a + 16);
        else if (!strncmp(a, "-runs=", 6)) runs = atol(a + 6);
        else if (!strncmp(a, "-timeout=", 9)) timeout_s = (unsigned)atoi(a + 9);
        else if (!strncmp(a, "-artifact_prefix=", 17)) prefix = a + 17;
        else if (!strncmp(a, "-merge=", 7)) merge = atoi(a + 7);
        else if (!strncmp(a, "-seed=", 6)) rng = (uint64_t)atoll(a + 6) | 1;
        else if (!strcmp(a, "-gen_seeds") && i + 1 < argc) return ksl_fuzz_write_seeds(argv[++i]);
        else if (a[0] == '-') continue;
        else if (ndirs < 64) dirs[ndirs++] = a;
        else {
            /* a single file: run it once (reproduce) */
        }
    }
    __sanitizer_set_death_callback(on_death);
    signal(SIGALRM, on_alarm);
    if (ndirs == 1) { struct stat st; if (!stat(dirs[0], &st) && S_ISREG(st.st_mode)) {   /* reproduce one input */
        FILE *f = fopen(dirs[0], "rb"); uint8_t *b = malloc((size_t)st.st_size + 1); size_t n = fread(b, 1, (size_t)st.st_size, f); fclose(f);
        run(b, n); printf("Executed %s: no finding\n", dirs[0]); return 0; } }
    if (ndirs) snprintf(outdir, sizeof outdir, "%s", dirs[0]);
    if (merge) {   /* -merge=1 A B C...: inputs of B, C... that add coverage beyond A go into A */
        load_dir(dirs[0], 1, 0);
        for (int i = 1; i < ndirs; i++) load_dir(dirs[i], 0, 1);
        printf("MERGE-OUTER: %zu files in the merged corpus, cov: %u\n", ncorpus, covered); return 0;
    }
    for (int i = 0; i < ndirs; i++) load_dir(dirs[i], 1, 0);
    if (!ncorpus) { uint8_t z = 0; run(&z, 1); add(&z, 1); }
    printf("INFO: loaded %zu inputs, cov: %u (driver: trace-pc-guard, %u guards)\n", ncorpus, covered, guards);
    time_t start = time(NULL), last = start; long execs = 0; uint8_t *buf = malloc(MAX_LEN);
    while ((runs < 0 || execs < runs) && (max_time <= 0 || time(NULL) - start < max_time)) {
        unit *u = &corpus[rnd() % ncorpus]; size_t n = u->n > MAX_LEN ? MAX_LEN : u->n; memcpy(buf, u->d, n);
        n = mutate(buf, n, MAX_LEN);
        execs++;
        if (run(buf, n)) { add(buf, n); if (ndirs) save(outdir, "", buf, n, 1);
            printf("#%ld\tNEW    cov: %u ft: %u corp: %zu exec/s: %ld\n", execs, covered, covered, ncorpus, execs / (long)(time(NULL) - start + 1)); fflush(stdout); }
        if (time(NULL) - last >= 30) { last = time(NULL);
            printf("#%ld\tpulse  cov: %u ft: %u corp: %zu exec/s: %ld\n", execs, covered, covered, ncorpus, execs / (long)(last - start + 1)); fflush(stdout); }
    }
    long secs = (long)(time(NULL) - start);
    printf("#%ld\tDONE   cov: %u ft: %u corp: %zu exec/s: %ld\n", execs, covered, covered, ncorpus, execs / (secs + 1));
    printf("Done %ld runs in %ld second(s)\n", execs, secs);
    return 0;
}
