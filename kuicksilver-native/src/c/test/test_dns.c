/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_dns_query: arguments checked before any lookup, answers bounded by cap, and on Linux a real exchange with a DNS server
 * on 127.0.0.1 that this test runs. KSL_LIVE_DNS=1 also asks the system's resolver for cloudflare.com's HTTPS records. */
#include "test_common.h"

#if defined(__linux__) && !defined(__ANDROID__)
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>

/* a response to `a.example HTTPS IN` with one record `1 . alpn=h3`; its ID is copied from the query */
static const uint8_t CANNED[] = {
    0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x01, 'a', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00, 0x00, 0x41, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0a,
    0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 'h', '3'};

typedef struct { int fd; int answer; uint16_t id; } fake_dns;

static void *fake_dns_run(void *arg) {
    fake_dns *f = arg; uint8_t q[512]; struct sockaddr_in from; socklen_t fl = sizeof from;
    struct pollfd p = { f->fd, POLLIN, 0 };
    if (poll(&p, 1, 5000) <= 0) return NULL;
    ssize_t n = recvfrom(f->fd, q, sizeof q, 0, (struct sockaddr *)&from, &fl);
    if (n < 12 || !f->answer) return NULL;   /* a silent server: the query times out */
    uint8_t r[sizeof CANNED]; memcpy(r, CANNED, sizeof r); r[0] = q[0]; r[1] = q[1]; f->id = (uint16_t)(q[0] << 8 | q[1]);
    sendto(f->fd, r, sizeof r, 0, (struct sockaddr *)&from, fl);
    return NULL;
}

/* binds the fake server on a free port of 127.0.0.1 and writes its KSL_UDP_ADDR_LEN address */
static int fake_dns_start(fake_dns *f, pthread_t *t, uint8_t addr[KSL_UDP_ADDR_LEN]) {
    f->fd = socket(AF_INET, SOCK_DGRAM, 0); if (f->fd < 0) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    if (bind(f->fd, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(f->fd, (struct sockaddr *)&a, &al) != 0) { close(f->fd); return -1; }
    memset(addr, 0, KSL_UDP_ADDR_LEN); addr[0] = 4; memcpy(addr + 2, &a.sin_port, 2); memcpy(addr + 4, &a.sin_addr, 4);
    return pthread_create(t, NULL, fake_dns_run, f);
}

static void dns_query_fake_server_linux(void) {
    fake_dns f = { -1, 1, 0 }; pthread_t t; uint8_t addr[KSL_UDP_ADDR_LEN];
    CHECK(fake_dns_start(&f, &t, addr) == 0, "fake DNS server started");
    uint8_t out[1024]; size_t len = 0;
    int r = ksl_dns_query("a.example", 65, addr, 2000, out, sizeof out, &len);
    pthread_join(t, NULL); close(f.fd);
    CHECK(r == KSL_OK, "the fake server's answer");
    CHECK(len == sizeof CANNED + 1 && out[0] == KSL_DNS_MESSAGE, "the whole message, after the kind byte");
    CHECK(len >= 3 && (uint16_t)(out[1] << 8 | out[2]) == f.id, "the answer's ID is the query's");
    CHECK(len == sizeof CANNED + 1 && !memcmp(out + 3, CANNED + 2, sizeof CANNED - 2), "the answer as sent");
}

static void dns_query_small_cap_fails_cleanly(void) {
    fake_dns f = { -1, 1, 0 }; pthread_t t; uint8_t addr[KSL_UDP_ADDR_LEN];
    CHECK(fake_dns_start(&f, &t, addr) == 0, "fake DNS server started");
    uint8_t out[40 + 8]; memset(out, 0xa5, sizeof out); size_t len = 7;
    int r = ksl_dns_query("a.example", 65, addr, 2000, out, 40, &len);   /* the answer is 49 bytes */
    pthread_join(t, NULL); close(f.fd);
    CHECK(r == KSL_ERROR && len == 0, "an answer larger than cap is an error");
    int untouched = 1; for (size_t i = 40; i < sizeof out; i++) untouched &= out[i] == 0xa5;
    CHECK(untouched, "nothing written past cap");
}

static void dns_query_timeout_bounded(void) {
    fake_dns f = { -1, 0, 0 }; pthread_t t; uint8_t addr[KSL_UDP_ADDR_LEN];
    CHECK(fake_dns_start(&f, &t, addr) == 0, "fake DNS server started");
    uint8_t out[512]; size_t len = 0;
    int r = ksl_dns_query("a.example", 65, addr, 200, out, sizeof out, &len);   /* two tries of one second at most */
    pthread_join(t, NULL); close(f.fd);
    CHECK(r == KSL_ERROR, "a server that never answers is an error");
}
#endif

static void dns_query_invalid_name(void) {
    char long_name[300]; memset(long_name, 'a', sizeof long_name - 1); long_name[sizeof long_name - 1] = 0;
    char long_label[80]; memset(long_label, 'b', 70); memcpy(long_label + 70, ".example", 9);
    const char *bad[] = { "", "a..example", ".example", "a b.example", "a\x01.example", long_name, long_label, NULL };
    uint8_t out[64]; size_t len = 5;
    for (int i = 0; bad[i]; i++) {
        len = 5;
        CHECK(ksl_dns_query(bad[i], 65, NULL, 1000, out, sizeof out, &len) == KSL_ERROR && len == 0, "a bad name is refused before a lookup");
    }
    CHECK(ksl_dns_query(NULL, 65, NULL, 1000, out, sizeof out, &len) == KSL_ERROR, "no name");
#if !defined(__ANDROID__)
    CHECK(ksl_dns_query("a.example", 65, NULL, 0, out, sizeof out, &len) == KSL_ERROR, "no time to ask");
    CHECK(ksl_dns_query("a.example", 65, NULL, 1000, NULL, 64, &len) == KSL_ERROR, "no buffer");
    CHECK(ksl_dns_query("a.example", 65, NULL, 1000, out, sizeof out, NULL) == KSL_ERROR, "no length");
#endif
}

static void dns_query_server_where_not_supported(void) {
#if defined(__APPLE__) || defined(_WIN32)
    uint8_t addr[KSL_UDP_ADDR_LEN] = { 6 };   /* an IPv6 server on port 0: neither platform takes it */
    uint8_t out[64]; size_t len = 0;
    CHECK(ksl_dns_query("a.example", 65, addr, 1000, out, sizeof out, &len) == KSL_DNS_NOT_SUPPORTED, "a server the platform cannot be told to ask");
#endif
}

static void dns_query_live(void) {
    const char *live = getenv("KSL_LIVE_DNS");
    if (!live || strcmp(live, "1") != 0) return;
    static uint8_t out[65536 + 1]; size_t len = 0;
    int r = ksl_dns_query("cloudflare.com", 65, NULL, 5000, out, sizeof out, &len);
    CHECK(r == KSL_OK && len > 1 && (out[0] == KSL_DNS_MESSAGE || out[0] == KSL_DNS_RECORDS), "cloudflare.com has HTTPS records");
    int h3 = 0; for (size_t i = 0; i + 3 <= len; i++) h3 |= out[i] == 2 && out[i + 1] == 'h' && out[i + 2] == '3';
    CHECK(h3, "and they offer h3");
    printf("dns live: %d, %zu bytes (kind %d)\n", r, len, len ? out[0] : 0);
}

void run_dns(void) {
    SECTION("dns");
    dns_query_invalid_name();
    dns_query_server_where_not_supported();
#if defined(__linux__) && !defined(__ANDROID__)
    dns_query_fake_server_linux();
    dns_query_small_cap_fails_cleanly();
    dns_query_timeout_bounded();
#endif
    dns_query_live();
    END();
}
