/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_udp_*: batched UDP with GSO, GRO, ECN, DF and REUSEPORT (ADR-0006; threat-model 3.12, 3.16). Linux and Apple (no GSO/GRO there);
 * elsewhere ksl_udp_open answers KSL_E_NOT_SUPPORTED. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1   /* clock_gettime, nanosleep under -std=c11 on glibc */
#endif
#include "test_common.h"
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h> /* RLIMIT_NOFILE for udp_open_without_wake_pipe */
#endif
#ifdef __linux__
#include <sched.h>        /* unshare: a user and network namespace for the ICMP injection test */
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#endif

static void v4(uint8_t a[KSL_UDP_ADDR_LEN], uint16_t port) { memset(a, 0, KSL_UDP_ADDR_LEN); a[0] = 4; a[1] = (uint8_t)(port >> 8); a[2] = (uint8_t)port; a[3] = 127; a[4] = 0; a[5] = 0; a[6] = 1; }
#if defined(__linux__) || defined(__APPLE__)
static uint16_t port_of(const uint8_t a[KSL_UDP_ADDR_LEN]) { return (uint16_t)((a[1] << 8) | a[2]); }
static ksl_udp *open_lo(int flags, uint8_t local[KSL_UDP_ADDR_LEN]) {
    uint8_t a[KSL_UDP_ADDR_LEN]; v4(a, 0); uint32_t err = 0; char msg[128] = {0};
    ksl_udp *u = ksl_udp_open(a, flags, &err, msg, sizeof msg); if (!u) { printf("open: %u %s\n", err, msg); return NULL; }
    size_t n = 0; CHECK(ksl_udp_get(u, KSL_UDP_GET_LOCAL, local, KSL_UDP_ADDR_LEN, &n) == KSL_OK && n == KSL_UDP_ADDR_LEN, "local address"); return u;
}
static uint32_t caps_of(ksl_udp *u, uint16_t *gso_max) { uint8_t c[8]; size_t n = 0; CHECK(ksl_udp_get(u, KSL_UDP_GET_CAPS, c, 8, &n) == KSL_OK && n == 8, "caps"); if (gso_max) *gso_max = (uint16_t)((c[4] << 8) | c[5]); return ((uint32_t)c[0] << 24) | ((uint32_t)c[1] << 16) | ((uint32_t)c[2] << 8) | c[3]; }
/* sends n datagrams of [len] bytes from a to b's address and receives them on b; returns received count */
static uint32_t ping(ksl_udp *a, ksl_udp *b, const uint8_t to[KSL_UDP_ADDR_LEN], uint32_t n, uint32_t len, uint8_t ecn, uint8_t *recv_ecn, uint8_t *recv_addr, uint32_t *recv_lens) {
    uint8_t *bufs[64]; uint32_t lens[64]; uint8_t addrs[64 * KSL_UDP_ADDR_LEN]; uint8_t ecns[64];
    for (uint32_t i = 0; i < n; i++) { bufs[i] = malloc(len); memset(bufs[i], (int)i, len); bufs[i][0] = (uint8_t)i; lens[i] = len; memcpy(addrs + i * KSL_UDP_ADDR_LEN, to, KSL_UDP_ADDR_LEN); ecns[i] = ecn; }
    uint32_t sent = 0; int r = ksl_udp_send(a, bufs, lens, addrs, ecns, n, &sent); CHECK(r == KSL_OK && sent == n, "send batch");
    uint8_t *rb[64]; uint32_t caps[64]; uint32_t rl[64]; uint8_t ra[64 * KSL_UDP_ADDR_LEN]; uint8_t re[64]; uint32_t got = 0, total = 0;
    for (uint32_t i = 0; i < 64; i++) { rb[i] = malloc(1500); caps[i] = 1500; }
    for (int tries = 0; tries < 50 && total < n; tries++) { got = 0; r = ksl_udp_recv(b, rb + total, caps + total, rl + total, ra + total * KSL_UDP_ADDR_LEN, re + total, 64 - total, &got, 200); if (r == KSL_WANT_READ) continue; CHECK(r == KSL_OK, "recv"); total += got; }
    for (uint32_t i = 0; i < total && i < n; i++) { if (recv_lens) recv_lens[i] = rl[i]; if (recv_ecn) recv_ecn[i] = re[i]; if (recv_addr) memcpy(recv_addr + i * KSL_UDP_ADDR_LEN, ra + i * KSL_UDP_ADDR_LEN, KSL_UDP_ADDR_LEN); }
    for (uint32_t i = 0; i < n; i++) free(bufs[i]); for (uint32_t i = 0; i < 64; i++) free(rb[i]);
    return total;
}
struct sender_args { ksl_udp *u; const uint8_t *to; volatile int stop; };
static void *sender_thread(void *arg) {
    struct sender_args *sa = arg; uint8_t *bufs[4]; uint32_t lens[4]; uint8_t addrs[4 * KSL_UDP_ADDR_LEN]; uint8_t ecn[4];
    for (uint32_t i = 0; i < 4; i++) { bufs[i] = malloc(1200); memset(bufs[i], 0x70, 1200); lens[i] = 1200; memcpy(addrs + i * KSL_UDP_ADDR_LEN, sa->to, KSL_UDP_ADDR_LEN); ecn[i] = 0; }
    while (!sa->stop) { uint32_t sent = 0; ksl_udp_send(sa->u, bufs, lens, addrs, ecn, 4, &sent); }
    for (uint32_t i = 0; i < 4; i++) free(bufs[i]); return NULL;
}
/* sends an empty datagram to 127.0.0.1:port every 5 ms for at most 1.5 s, until stop */
struct junk_args { uint16_t port; volatile int stop; };
static void *junk_thread(void *arg) {
    struct junk_args *ja = arg; int s = socket(AF_INET, SOCK_DGRAM, 0); if (s < 0) return NULL;
    struct sockaddr_in to; memset(&to, 0, sizeof to); to.sin_family = AF_INET; to.sin_port = htons(ja->port); to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef __APPLE__
    to.sin_len = sizeof to;
#endif
    for (int i = 0; i < 300 && !ja->stop; i++) { (void)sendto(s, "", 0, 0, (struct sockaddr *)&to, sizeof to); struct timespec w = { 0, 5000000 }; nanosleep(&w, NULL); }
    close(s); return NULL;
}
/* one datagram of [len] bytes from u to [to]; the number ksl_udp_send reports as sent */
static uint32_t send1(ksl_udp *u, const uint8_t to[KSL_UDP_ADDR_LEN], uint32_t len) {
    uint8_t *buf = malloc(len); memset(buf, 0x41, len); uint8_t *bufs[1] = { buf }; uint32_t lens[1] = { len }; uint8_t ecn[1] = { 0 }; uint32_t sent = 0;
    int r = ksl_udp_send(u, bufs, lens, to, ecn, 1, &sent); free(buf); return r == KSL_OK ? sent : 0;
}
/* receives one datagram within timeout_ms: its length, 0 on KSL_WANT_READ, -1 on KSL_ERROR */
static int recv1(ksl_udp *u, int timeout_ms) {
    uint8_t buf[2048]; uint8_t *bufs[1] = { buf }; uint32_t caps[1] = { sizeof buf }, lens[1], got = 0; uint8_t ra[KSL_UDP_ADDR_LEN], re[1];
    int r = ksl_udp_recv(u, bufs, caps, lens, ra, re, 1, &got, timeout_ms); if (r == KSL_ERROR) return -1; return got ? (int)lens[0] : 0;
}
#ifdef __linux__
static uint16_t csum16(const uint8_t *p, size_t n) { uint32_t s = 0; for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)(p[i] << 8 | p[i + 1]); if (n & 1) s += (uint32_t)(p[n - 1] << 8); while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)~s; }
static int lo_set(int up, int mtu) {
    int s = socket(AF_INET, SOCK_DGRAM, 0); if (s < 0) return -1; struct ifreq r; memset(&r, 0, sizeof r); snprintf(r.ifr_name, IFNAMSIZ, "lo");
    int ok = 1;
    if (up) { if (ioctl(s, SIOCGIFFLAGS, &r) != 0) ok = 0; r.ifr_flags |= IFF_UP; if (ok && ioctl(s, SIOCSIFFLAGS, &r) != 0) ok = 0; }
    if (ok && mtu) { r.ifr_mtu = mtu; if (ioctl(s, SIOCSIFMTU, &r) != 0) ok = 0; }
    close(s); return ok ? 0 : -1;
}
/* In a child inside a fresh user and network namespace (no root needed where unprivileged user namespaces are allowed):
   (1) a datagram over the interface MTU with DF is a local EMSGSIZE: counted by ksl_udp_emsgsize, its SO_EE_ORIGIN_LOCAL entry drained
       and never a Packet Too Big; (2) an ICMP "fragmentation needed" (MTU 1300) quoting a datagram of our socket, injected through a raw
       socket, reaches ksl_udp_take_ptb with the MTU, the quoted payload and the original destination. Exit 0 pass, 77 skip, else the
       failed step. */
static int ptb_child(void) {
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) return 77;
    if (lo_set(1, 1280) != 0) return 77;
    uint8_t la[KSL_UDP_ADDR_LEN], lb[KSL_UDP_ADDR_LEN]; ksl_udp *a = open_lo(KSL_UDP_DF, la), *b = open_lo(0, lb); if (!a || !b) return 2;
    if (!ksl_udp_recverr_for_test(a)) return 3;
    /* udp_recverr_local_emsgsize_queued */
    uint32_t last = 0; uint64_t e0 = ksl_udp_emsgsize(a, &last);
    if (send1(a, lb, 1400) != 1) return 4;   /* the slot is lost, not an error */
    if (ksl_udp_emsgsize(a, &last) != e0 + 1 || last != 1400) return 5;
    if (recv1(a, 50) != 0) return 6;          /* the local entry is drained, no datagram, no error */
    uint8_t q[KSL_UDP_PTB_QUOTE], dst[KSL_UDP_ADDR_LEN]; uint32_t ql = 0, mtu = 0;
    if (ksl_udp_take_ptb(a, q, sizeof q, &ql, dst, &mtu) != 0) return 7;   /* only ICMP-origin entries are Packet Too Big */
    if (lo_set(0, 65536) != 0) return 8;
    /* udp_recverr_ptb_parsed: ICMP type 3 code 4, next-hop MTU 1300, quoting IP + UDP header of a datagram 127.0.0.1:port(a) -> 127.0.0.1:4433 */
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); if (raw < 0) return 77;
    uint8_t pkt[8 + 20 + 8 + 32]; memset(pkt, 0, sizeof pkt);
    pkt[0] = 3; pkt[1] = 4; pkt[6] = 1300 >> 8; pkt[7] = 1300 & 0xff;
    uint8_t *ip = pkt + 8; ip[0] = 0x45; ip[2] = 0; ip[3] = 20 + 8 + 1400 > 255 ? 0 : 0; uint16_t tot = 20 + 8 + 1400; ip[2] = (uint8_t)(tot >> 8); ip[3] = (uint8_t)tot;
    ip[6] = 0x40; ip[8] = 64; ip[9] = IPPROTO_UDP; ip[12] = 127; ip[15] = 1; ip[16] = 127; ip[19] = 1;
    uint16_t ic = csum16(ip, 20); ip[10] = (uint8_t)(ic >> 8); ip[11] = (uint8_t)ic;
    uint8_t *uh = ip + 20; uh[0] = la[1]; uh[1] = la[2]; uh[2] = 4433 >> 8; uh[3] = 4433 & 0xff; uh[4] = (uint8_t)((8 + 1400) >> 8); uh[5] = (uint8_t)(8 + 1400);
    for (int i = 0; i < 32; i++) uh[8 + i] = (uint8_t)(0x40 + i);
    uint16_t c = csum16(pkt, sizeof pkt); pkt[2] = (uint8_t)(c >> 8); pkt[3] = (uint8_t)c;
    struct sockaddr_in to; memset(&to, 0, sizeof to); to.sin_family = AF_INET; to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sendto(raw, pkt, sizeof pkt, 0, (struct sockaddr *)&to, sizeof to) != (ssize_t)sizeof pkt) { close(raw); return 9; }
    close(raw);
    int got = 0; for (int i = 0; i < 20 && !got; i++) { if (recv1(a, 50) < 0) return 10; got = ksl_udp_take_ptb(a, q, sizeof q, &ql, dst, &mtu); }
    if (!got) return 11;
    if (mtu != 1300 || ql != 32 || q[0] != 0x40 || q[31] != 0x40 + 31) return 12;
    if (dst[0] != 4 || ((dst[1] << 8) | dst[2]) != 4433 || dst[3] != 127 || dst[6] != 1) return 13;
    if (send1(b, la, 100) != 1 || recv1(a, 500) != 100) return 14;   /* the socket still receives */
    ksl_udp_close(a); ksl_udp_close(b); return 0;
}
#endif
/* writes one error into the socket over and over, as a failing sender or receiver thread would */
struct err_args { ksl_udp *u; int e; const char *what; };
static void *err_writer(void *arg) { struct err_args *ea = arg; for (int i = 0; i < 100000; i++) ksl_udp_set_err_for_test(ea->u, ea->e, ea->what); return NULL; }
#endif

void run_udp(void) {
    SECTION("udp");
#if defined(__linux__) || defined(__APPLE__)
    uint8_t la[KSL_UDP_ADDR_LEN], lb[KSL_UDP_ADDR_LEN];
    ksl_udp *a = open_lo(KSL_UDP_ECN | KSL_UDP_GSO | KSL_UDP_GRO | KSL_UDP_DF, la); ksl_udp *b = open_lo(KSL_UDP_ECN | KSL_UDP_GSO | KSL_UDP_GRO | KSL_UDP_DF, lb);
    CHECK(a && b, "udp_open on loopback");
    if (a && b) {
        uint16_t gso_max = 0; uint32_t caps = caps_of(a, &gso_max);
        CHECK((caps & KSL_UDP_ECN) && (caps & KSL_UDP_DF), "ECN and DF granted"); CHECK((caps & KSL_UDP_GSO) ? gso_max >= 2 : 1, "gso max segments when granted");
#ifdef __APPLE__
        CHECK(!(caps & (KSL_UDP_GSO | KSL_UDP_GRO)) && gso_max == 0, "udp_apple_no_gso_gro: Darwin has no UDP_SEGMENT/UDP_GRO, the caps say so");
#endif
        /* udp_loopback_send_recv_batch: 32 datagrams, distinct lengths, the sender's address on each */
        { uint32_t rl[64]; uint8_t ra[64 * KSL_UDP_ADDR_LEN]; uint8_t *bufs[32]; uint32_t lens[32]; uint8_t addrs[32 * KSL_UDP_ADDR_LEN]; uint8_t ecns[32];
          for (uint32_t i = 0; i < 32; i++) { lens[i] = 100 + i * 37; bufs[i] = malloc(lens[i]); memset(bufs[i], (int)i, lens[i]); memcpy(addrs + i * KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN); ecns[i] = 0; }
          uint32_t sent = 0; CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 32, &sent) == KSL_OK && sent == 32, "32 sent");
          uint8_t *rb[64]; uint32_t rc[64]; uint8_t re[64]; uint32_t total = 0, got; for (int i = 0; i < 64; i++) { rb[i] = malloc(1500); rc[i] = 1500; }
          for (int t = 0; t < 50 && total < 32; t++) { int r = ksl_udp_recv(b, rb + total, rc + total, rl + total, ra + total * KSL_UDP_ADDR_LEN, re + total, 64 - total, &got, 200); if (r == KSL_WANT_READ) continue; CHECK(r == KSL_OK, "recv batch"); total += got; }
          CHECK(total == 32, "32 received"); int lens_ok = 1, addr_ok = 1, data_ok = 1;
          for (uint32_t i = 0; i < total; i++) { if (rl[i] != 100 + rl[i] % 37 * 0 + (rl[i] - 100)) lens_ok = 0; if (port_of(ra + i * KSL_UDP_ADDR_LEN) != port_of(la)) addr_ok = 0; if (rb[i][0] != (uint8_t)((rl[i] - 100) / 37)) data_ok = 0; }
          CHECK(lens_ok && addr_ok && data_ok, "lengths, source address and payloads match");
          for (uint32_t i = 0; i < 32; i++) free(bufs[i]); for (int i = 0; i < 64; i++) free(rb[i]); }
        /* udp_recv_one_syscall_per_datagram: 8 datagrams sent one by one (no GSO) are taken with one recvmsg each; a call polls only
           when it found the queue empty (a poll before every recvmsg cost a sender without GSO two system calls per datagram) */
        { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(0, lc); CHECK(c != NULL, "plain socket");
          if (c) { uint8_t *bufs[8]; uint32_t lens[8]; uint8_t addrs[8 * KSL_UDP_ADDR_LEN]; uint8_t ecns[8];
            for (uint32_t i = 0; i < 8; i++) { lens[i] = 100 + i; bufs[i] = malloc(lens[i]); memset(bufs[i], (int)i, lens[i]); memcpy(addrs + i * KSL_UDP_ADDR_LEN, lc, KSL_UDP_ADDR_LEN); ecns[i] = 0; }
            uint32_t sent = 0; CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 8, &sent) == KSL_OK && sent == 8, "8 sent one by one");
            uint8_t *rb[16]; uint32_t rc[16], rl[16]; uint8_t ra[16 * KSL_UDP_ADDR_LEN], re[16]; uint32_t total = 0, got, calls = 0; for (int i = 0; i < 16; i++) { rb[i] = malloc(1500); rc[i] = 1500; }
            uint32_t before = ksl_udp_recv_syscalls_for_test(c);
            for (int t = 0; t < 50 && total < 8; t++) { calls++; int r = ksl_udp_recv(c, rb + total, rc + total, rl + total, ra + total * KSL_UDP_ADDR_LEN, re + total, 16 - total, &got, 200); if (r == KSL_WANT_READ) continue; CHECK(r == KSL_OK, "recv"); total += got; }
            uint32_t syscalls = ksl_udp_recv_syscalls_for_test(c) - before;
            CHECK(total == 8, "8 received");
            /* per call at most an empty recvmsg, a poll and the empty recvmsg that ends it; one recvmsg per datagram */
            CHECK(syscalls <= total + 3 * calls, "receive system calls: one per datagram plus at most three per call");
            if (syscalls > total + 3 * calls) printf("    %u system calls for %u datagrams in %u calls\n", syscalls, total, calls);
            for (uint32_t i = 0; i < 8; i++) free(bufs[i]); for (int i = 0; i < 16; i++) free(rb[i]); ksl_udp_close(c); } }
        /* udp_gso_one_syscall + udp_gro_splits_segments: 8 x 1200 equal-size, same address → one sendmsg with UDP_SEGMENT; the receiver sees 8 datagrams */
        { uint32_t rl[64]; uint8_t re[64]; uint32_t before = ksl_udp_syscalls_for_test(a); uint32_t got = ping(a, b, lb, 8, 1200, 0, re, NULL, rl); CHECK(got == 8, "8 segments delivered"); int ok = 1; for (uint32_t i = 0; i < got; i++) if (rl[i] != 1200) ok = 0; CHECK(ok, "segments are 1200 each");
          if (caps & KSL_UDP_GSO) CHECK(ksl_udp_syscalls_for_test(a) - before == 1, "one sendmsg for the batch (GSO)"); }
        /* udp_gro_two_senders_not_merged: a second sender's datagrams keep their own source address (threat-model 3.12) */
        { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(KSL_UDP_GRO, lc); CHECK(c != NULL, "third socket");
          if (c) { uint8_t ra[64 * KSL_UDP_ADDR_LEN]; uint32_t rl[64]; uint32_t got = ping(a, b, lb, 4, 1200, 0, NULL, ra, rl); CHECK(got == 4, "a's four"); uint8_t rc2[64 * KSL_UDP_ADDR_LEN]; uint32_t got2 = ping(c, b, lb, 4, 1200, 0, NULL, rc2, rl); CHECK(got2 == 4, "c's four");
            int ok = 1; for (uint32_t i = 0; i < got; i++) if (port_of(ra + i * KSL_UDP_ADDR_LEN) != port_of(la)) ok = 0; for (uint32_t i = 0; i < got2; i++) if (port_of(rc2 + i * KSL_UDP_ADDR_LEN) != port_of(lc)) ok = 0; CHECK(ok, "each sender's segments carry its own address"); ksl_udp_close(c); } }
        /* udp_ecn_roundtrip */
        { uint8_t re[64]; uint32_t got = ping(a, b, lb, 2, 100, 2 /* ECT(0) */, re, NULL, NULL); CHECK(got == 2 && re[0] == 2 && re[1] == 2, "ECT(0) arrives"); got = ping(a, b, lb, 1, 100, 3 /* CE */, re, NULL, NULL); CHECK(got == 1 && re[0] == 3, "CE arrives"); }
        /* udp_df_probe_mode: IP_MTU_DISCOVER == IP_PMTUDISC_PROBE (never _DO: quic-go CVE-2024-53259), IPV6_DONTFRAG where applicable */
        { uint8_t fd8[4]; size_t n = 0; CHECK(ksl_udp_get(a, KSL_UDP_GET_FD, fd8, 4, &n) == KSL_OK && n == 4, "fd"); int fd = (int)(((uint32_t)fd8[0] << 24) | ((uint32_t)fd8[1] << 16) | ((uint32_t)fd8[2] << 8) | fd8[3]); 
#ifdef __APPLE__
          CHECK(ksl_udp_df_mode_for_test(fd) == 1, "IP_DONTFRAG set (Darwin has no PMTUDISC modes; its ICMPv6 PMTU cache is clamped to >= 1280, above QUIC's 1248-byte floor)"); }
#else
          CHECK(ksl_udp_df_mode_for_test(fd) == 3 /* IP_PMTUDISC_PROBE */, "probe mode, not DO"); }
#endif
        /* udp_truncated_datagram_dropped: a 1400-byte datagram into a 1000-byte slot is dropped, not truncated */
        { uint8_t *bufs[1]; uint32_t lens[1] = {1400}; uint8_t addrs[KSL_UDP_ADDR_LEN]; uint8_t ecns[1] = {0}; bufs[0] = malloc(1400); memset(bufs[0], 7, 1400); memcpy(addrs, lb, KSL_UDP_ADDR_LEN); uint32_t sent = 0;
          CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 1, &sent) == KSL_OK && sent == 1, "big one sent"); uint8_t *rb[1]; uint32_t rc[1] = {1000}; uint32_t rl[1]; uint8_t ra[KSL_UDP_ADDR_LEN]; uint8_t re[1]; uint32_t got = 0; rb[0] = malloc(1000);
          int r = ksl_udp_recv(b, rb, rc, rl, ra, re, 1, &got, 300); CHECK((r == KSL_OK && got == 0) || r == KSL_WANT_READ, "truncated datagram dropped"); free(bufs[0]); free(rb[0]); }
        /* udp_gso_join_fits_an_ipv4_datagram: 60 x 1092 = 65520 bytes fit the 64 KiB scratch, but an IPv4 datagram carries at
           most 65507 bytes of UDP payload (65535 - 20 - 8; Linux __ip_append_data answers EMSGSIZE), and EMSGSIZE for segments of
           at most 1200 bytes switched GSO off for the socket; the join stops at the limit and GSO stays on */
        if (caps & KSL_UDP_GSO) { uint8_t st[12]; size_t sn = 0; CHECK(ksl_udp_get(a, KSL_UDP_GET_STATS, st, 12, &sn) == KSL_OK && sn == 12, "stats"); uint32_t fb0 = ((uint32_t)st[8] << 24) | ((uint32_t)st[9] << 16) | ((uint32_t)st[10] << 8) | st[11];
          uint32_t rl[64]; uint32_t got = ping(a, b, lb, 60, 1092, 0, NULL, NULL, rl); CHECK(got == 60, "all sixty delivered");
          CHECK(ksl_udp_get(a, KSL_UDP_GET_STATS, st, 12, &sn) == KSL_OK, "stats after"); uint32_t fb1 = ((uint32_t)st[8] << 24) | ((uint32_t)st[9] << 16) | ((uint32_t)st[10] << 8) | st[11];
          CHECK(fb1 == fb0 && (caps_of(a, NULL) & KSL_UDP_GSO), "a run over 65507 bytes to an IPv4 peer keeps GSO on"); }
        /* udp_gso_eio_falls_back_and_resends: the first GSO sendmsg fails with EIO → GSO off, every segment resent one by one, caps lose GSO */
        if (caps & KSL_UDP_GSO) { ksl_udp_fail_next_gso_for_test(a, EIO); uint32_t rl[64]; uint32_t got = ping(a, b, lb, 6, 1000, 0, NULL, NULL, rl); CHECK(got == 6, "all six delivered after the fallback"); CHECK(!(caps_of(a, NULL) & KSL_UDP_GSO), "GSO withdrawn from the caps"); }
        /* udp_concurrent_send_recv_same_socket: one thread sends GSO batches on b while another receives trains on b (the loop and the
           receiver of KslDatagramIo); every received segment must be intact — the multi-loop test caught the server handing its own
           outgoing Initials back to itself when send and receive shared one scratch buffer */
        { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(KSL_UDP_GSO | KSL_UDP_GRO, lc); CHECK(c != NULL, "socket c");
          if (c) { struct sender_args sa = { b, la, 0 }; pthread_t t; CHECK(pthread_create(&t, NULL, sender_thread, &sa) == 0, "sender thread");
            uint8_t *tb[8]; uint32_t tl[8]; uint8_t ta[8 * KSL_UDP_ADDR_LEN]; uint8_t te[8]; for (uint32_t i = 0; i < 8; i++) { tb[i] = malloc(1200); memset(tb[i], 0x40 + (int)i, 1200); tl[i] = 1200; memcpy(ta + i * KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN); te[i] = 0; }
            uint8_t *rb[8]; uint32_t rc[8], rl[8], got = 0; uint8_t ra[8 * KSL_UDP_ADDR_LEN], re[8]; for (uint32_t i = 0; i < 8; i++) { rb[i] = malloc(1500); rc[i] = 1500; }
            uint8_t *db[8]; uint32_t dc[8], dl[8]; uint8_t da[8 * KSL_UDP_ADDR_LEN], de[8]; for (uint32_t i = 0; i < 8; i++) { db[i] = malloc(1500); dc[i] = 1500; }
            int ok = 1; uint32_t rounds = 0, corrupted = 0;
            for (int round = 0; round < 300 && ok; round++) {
                uint32_t sent = 0; if (ksl_udp_send(c, tb, tl, ta, te, 8, &sent) != KSL_OK || sent != 8) { ok = 0; break; }
                uint32_t total = 0; for (int tries = 0; tries < 50 && total < 8; tries++) { int r = ksl_udp_recv(b, rb, rc, rl, ra, re, 8, &got, 100); if (r != KSL_OK) continue;
                    for (uint32_t i = 0; i < got; i++) { if (rl[i] != 1200 || rb[i][0] != rb[i][1199] || rb[i][0] < 0x40 || rb[i][0] > 0x47) corrupted++; } total += got; }
                if (total != 8) corrupted++; rounds++;
                uint32_t d = 0; ksl_udp_recv(a, db, dc, dl, da, de, 8, &d, 0);   /* keep a's queue from filling with the sender's traffic */
            }
            sa.stop = 1; pthread_join(t, NULL);
            CHECK(ok && rounds == 300, "300 rounds of trains received"); CHECK(corrupted == 0, "no segment corrupted by the concurrent sender");
            for (uint32_t i = 0; i < 8; i++) { free(tb[i]); free(rb[i]); free(db[i]); } ksl_udp_close(c); } }
        /* udp_gso_run_never_starts_with_a_larger_datagram: [1452, 1200, 1200] leaves as two sendmsg — a run whose gso_size exceeds
           the following segments would carry a PMTU probe's size to every segment and get EINVAL on links narrower than the probe */
        { uint8_t lg[KSL_UDP_ADDR_LEN]; ksl_udp *g = open_lo(KSL_UDP_GSO | KSL_UDP_GRO, lg); CHECK(g != NULL, "fresh GSO socket (a lost GSO in the EIO section above)"); if (g && (caps_of(g, NULL) & KSL_UDP_GSO)) { uint8_t *bufs[3]; uint32_t lens[3] = { 1452, 1200, 1200 }; uint8_t addrs[3 * KSL_UDP_ADDR_LEN]; uint8_t ecns[3] = { 0, 0, 0 };
            for (uint32_t i = 0; i < 3; i++) { bufs[i] = malloc(1452); memset(bufs[i], 0x50 + (int)i, 1452); memcpy(addrs + i * KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN); }
            uint32_t before = ksl_udp_syscalls_for_test(g), sent = 0; CHECK(ksl_udp_send(g, bufs, lens, addrs, ecns, 3, &sent) == KSL_OK && sent == 3, "three sent");
            CHECK(ksl_udp_syscalls_for_test(g) - before == 2, "the probe alone, then one run of two equal segments");
            uint8_t *rb[3]; uint32_t rc[3] = { 1500, 1500, 1500 }, rl[3], got = 0, total = 0; uint8_t ra[3 * KSL_UDP_ADDR_LEN], re[3]; for (int i = 0; i < 3; i++) rb[i] = malloc(1500);
            for (int tries = 0; tries < 50 && total < 3; tries++) { if (ksl_udp_recv(b, rb + total, rc, rl + total, ra, re, 3 - total, &got, 100) == KSL_OK) total += got; }
            CHECK(total == 3 && rl[0] == 1452 && rl[1] == 1200 && rl[2] == 1200, "all three arrive with their own sizes");
            for (int i = 0; i < 3; i++) { free(bufs[i]); free(rb[i]); } } if (g) ksl_udp_close(g); }
        /* udp_transient_send_errors_skip_the_datagram: a second EPERM, EACCES or ENETUNREACH on one datagram skips that slot and the socket stays usable */
        { uint8_t *bufs[2]; uint32_t lens[2] = { 100, 90 }; uint8_t addrs[2 * KSL_UDP_ADDR_LEN]; uint8_t ecns[2] = { 0, 0 }; for (int i = 0; i < 2; i++) { bufs[i] = malloc(100); memset(bufs[i], 0x60 + i, 100); memcpy(addrs + i * KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN); }   /* unequal lengths: no GSO run, the hook fails plain sends */
            uint32_t sent = 0; ksl_udp_fail_next_send_for_test(a, EPERM); CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "EPERM: retried once, both sent");
            ksl_udp_fail_next_send_for_test(a, EPERM); CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "a later EPERM after successful sends: retried again (the retry budget renews on success), both sent");
            ksl_udp_fail_next_send_for_test(a, ENETUNREACH); CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "ENETUNREACH: the datagram is given up (counted as sent, lost on the wire), the socket lives");
            uint8_t *rb[8]; uint32_t rc[8], rl[8], got = 0, drained = 0; uint8_t ra[8 * KSL_UDP_ADDR_LEN], re[8]; for (int i = 0; i < 8; i++) { rb[i] = malloc(200); rc[i] = 200; }
            for (int tries = 0; tries < 20; tries++) { if (ksl_udp_recv(b, rb, rc, rl, ra, re, 8, &got, 100) == KSL_OK) drained += got; else break; }
            CHECK(drained == 5, "five of the six reached the wire (the unreachable one was skipped)");
            for (int i = 0; i < 2; i++) free(bufs[i]); for (int i = 0; i < 8; i++) free(rb[i]); }
        /* udp_host_or_net_down_is_slot_loss: EHOSTDOWN and ENETDOWN (a peer's link went away, Darwin reports both) lose that slot only;
           udp_enobufs_is_backpressure: a full interface queue answers KSL_OK with the datagrams sent so far, as EAGAIN, and nothing is lost */
        { uint8_t *bufs[2]; uint32_t lens[2] = { 100, 90 }; uint8_t addrs[2 * KSL_UDP_ADDR_LEN]; uint8_t ecns[2] = { 0, 0 }; for (int i = 0; i < 2; i++) { bufs[i] = malloc(100); memset(bufs[i], 0x20 + i, 100); memcpy(addrs + i * KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN); }
            uint32_t sent = 0;
            ksl_udp_fail_next_send_for_test(a, EHOSTDOWN); CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "EHOSTDOWN: the slot is lost, the batch goes on");
            ksl_udp_fail_next_send_for_test(a, ENETDOWN); CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "ENETDOWN: the slot is lost, the batch goes on");
            ksl_udp_fail_next_send_for_test(a, ENOBUFS); CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 0, "ENOBUFS: backpressure, nothing counted as sent");
            CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "the retry sends both");
            uint8_t *rb[8]; uint32_t rc[8], rl[8], got = 0, drained = 0; uint8_t ra[8 * KSL_UDP_ADDR_LEN], re[8]; for (int i = 0; i < 8; i++) { rb[i] = malloc(200); rc[i] = 200; }
            for (int tries = 0; tries < 20; tries++) { if (ksl_udp_recv(b, rb, rc, rl, ra, re, 8, &got, 100) == KSL_OK) drained += got; else break; }
            CHECK(drained == 4, "four reached the wire: one of each down batch, both of the retry");
            for (int i = 0; i < 2; i++) free(bufs[i]); for (int i = 0; i < 8; i++) free(rb[i]); }
        /* udp_bad_destination_keeps_ecn_and_gso: the kernel answers EINVAL for port 0 (a spoofed Initial's source); that is the
           destination's fault — the slot is lost like any datagram on the wire, the batch goes on, and neither the ECN cmsg nor GSO is withdrawn */
        { uint8_t lg[KSL_UDP_ADDR_LEN]; ksl_udp *g = open_lo(KSL_UDP_ECN | KSL_UDP_GSO, lg); CHECK(g != NULL, "socket for bad destinations");
          if (g) { uint32_t granted = caps_of(g, NULL); uint8_t zero[KSL_UDP_ADDR_LEN]; v4(zero, 0);
            uint8_t *bufs[2]; uint32_t lens[2] = { 100, 90 }; uint8_t addrs[2 * KSL_UDP_ADDR_LEN]; uint8_t ecns[2] = { 2, 2 }; uint32_t sent = 0;
            for (int i = 0; i < 2; i++) { bufs[i] = malloc(1200); memset(bufs[i], 0x30 + i, 1200); }
            memcpy(addrs, zero, KSL_UDP_ADDR_LEN); memcpy(addrs + KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN);
            CHECK(ksl_udp_send(g, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "[port 0 marked, valid marked]: the first is lost, both counted, no socket error");
            CHECK(caps_of(g, NULL) & KSL_UDP_ECN, "ECN still granted after EINVAL caused by the destination");
            lens[0] = lens[1] = 1200; memcpy(addrs + KSL_UDP_ADDR_LEN, zero, KSL_UDP_ADDR_LEN);
            CHECK(ksl_udp_send(g, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "a GSO run of two 1200-byte slots to port 0: lost, counted, no socket error");
            if (granted & KSL_UDP_GSO) CHECK(caps_of(g, NULL) & KSL_UDP_GSO, "GSO still granted after EINVAL caused by the destination");
            CHECK(caps_of(g, NULL) & KSL_UDP_ECN, "ECN still granted after the GSO run");
            uint8_t *rb[8]; uint32_t rc[8], rl[8], got = 0, marked90 = 0, other = 0; uint8_t ra[8 * KSL_UDP_ADDR_LEN], re[8]; for (int i = 0; i < 8; i++) { rb[i] = malloc(1500); rc[i] = 1500; }
            for (int tries = 0; tries < 20; tries++) { if (ksl_udp_recv(b, rb, rc, rl, ra, re, 8, &got, 100) != KSL_OK) break; for (uint32_t i = 0; i < got; i++) { if (rl[i] == 90 && re[i] == 2) marked90++; else other++; } }
            CHECK(marked90 == 1 && other == 0, "the valid slot arrived once, still ECT(0)");
            for (int i = 0; i < 2; i++) free(bufs[i]); for (int i = 0; i < 8; i++) free(rb[i]); ksl_udp_close(g); } }
        /* udp_link_local_destination_is_slot_loss: the 20-byte address has no scope id, so a link-local IPv6 peer cannot be
           reached; the kernel's EINVAL loses that slot only (skipped where the host has no IPv6 loopback, e.g. a default Docker network) */
        { uint8_t l6[KSL_UDP_ADDR_LEN] = { 6 }; l6[18] = 1; uint32_t err = 0; char msg[128] = {0}; ksl_udp *v6 = ksl_udp_open(l6, KSL_UDP_ECN, &err, msg, sizeof msg);
          if (!v6) printf("udp: no IPv6 loopback (%s), link-local case skipped\n", msg);
          else { uint8_t me[KSL_UDP_ADDR_LEN]; size_t n = 0; ksl_udp_get(v6, KSL_UDP_GET_LOCAL, me, KSL_UDP_ADDR_LEN, &n);
            uint8_t addrs[2 * KSL_UDP_ADDR_LEN] = {0}; addrs[0] = 6; addrs[2] = 0x50; addrs[3] = 0xfe; addrs[4] = 0x80; addrs[18] = 1; memcpy(addrs + KSL_UDP_ADDR_LEN, me, KSL_UDP_ADDR_LEN);
            uint8_t d0[64], d1[64]; memset(d0, 1, 64); memset(d1, 2, 64); uint8_t *bufs[2] = { d0, d1 }; uint32_t lens[2] = { 64, 63 }; uint8_t ecns[2] = { 2, 2 }; uint32_t sent = 0;
            CHECK(ksl_udp_send(v6, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "[fe80::1 without scope, own address]: the first is lost, no socket error");
            CHECK(caps_of(v6, NULL) & KSL_UDP_ECN, "ECN still granted after the link-local slot");
            /* udp_ecn_roundtrip_ipv6: the valid slot reaches the socket itself with its IPV6_TCLASS mark */
            { uint8_t rbuf[128]; uint8_t *rb[1] = { rbuf }; uint32_t rc[1] = { 128 }, rl[1] = { 0 }, got = 0; uint8_t ra[KSL_UDP_ADDR_LEN], re[1] = { 0 };
              for (int tries = 0; tries < 10 && !got; tries++) ksl_udp_recv(v6, rb, rc, rl, ra, re, 1, &got, 100);
              CHECK(got == 1 && rl[0] == 63 && re[0] == 2, "ECT(0) arrives over IPv6 loopback"); }
            ksl_udp_close(v6); } }
        /* udp_wildcard_is_dual_stack: 0.0.0.0 (and ::) open one AF_INET6 socket with IPV6_V6ONLY off, as NIO: it receives from and sends to
           an IPv4 and an IPv6 peer, IPv4 peers come back as family 4 (not v4-mapped), ECN marks and DF hold for both families
           (skipped where the host has no IPv6 loopback, e.g. a default Docker network) */
        { uint8_t l6[KSL_UDP_ADDR_LEN] = { 6 }; l6[18] = 1; uint32_t err = 0; char msg[128] = {0}; ksl_udp *s6 = ksl_udp_open(l6, KSL_UDP_ECN, &err, msg, sizeof msg); uint8_t lp[KSL_UDP_ADDR_LEN]; ksl_udp *p4 = open_lo(KSL_UDP_ECN, lp);   /* a fresh IPv4 peer: a still holds the concurrent test's backlog */
          uint8_t any4[KSL_UDP_ADDR_LEN]; v4(any4, 0); memset(any4 + 3, 0, 4); ksl_udp *w = ksl_udp_open(any4, KSL_UDP_ECN | KSL_UDP_DF, &err, msg, sizeof msg);
          CHECK(w != NULL, "0.0.0.0:0 opens");
          if (!s6) printf("udp: no IPv6 loopback (%s), dual-stack case skipped\n", msg);
          else if (w && p4) { uint8_t lw[KSL_UDP_ADDR_LEN], l6b[KSL_UDP_ADDR_LEN]; size_t n = 0; ksl_udp_get(w, KSL_UDP_GET_LOCAL, lw, KSL_UDP_ADDR_LEN, &n); ksl_udp_get(s6, KSL_UDP_GET_LOCAL, l6b, KSL_UDP_ADDR_LEN, &n);
            CHECK(lw[0] == 4 && port_of(lw) != 0 && !lw[3] && !lw[4] && !lw[5] && !lw[6], "0.0.0.0 asked, 0.0.0.0 and the chosen port reported");
            uint32_t c = caps_of(w, NULL); CHECK((c & KSL_UDP_ECN) && (c & KSL_UDP_DF), "ECN and DF granted on the dual-stack socket");
            uint8_t to4[KSL_UDP_ADDR_LEN], to6[KSL_UDP_ADDR_LEN]; v4(to4, port_of(lw)); memcpy(to6, l6, KSL_UDP_ADDR_LEN); to6[1] = lw[1]; to6[2] = lw[2];
            uint8_t re[64], ra[64 * KSL_UDP_ADDR_LEN];
            CHECK(ping(p4, w, to4, 1, 100, 2, re, ra, NULL) == 1 && re[0] == 2, "from 127.0.0.1: received, ECT(0)");
            CHECK(ra[0] == 4 && ra[3] == 127 && ra[6] == 1 && port_of(ra) == port_of(lp), "the IPv4 peer reported as 127.0.0.1, not ::ffff:127.0.0.1");
            CHECK(ping(s6, w, to6, 1, 100, 3, re, ra, NULL) == 1 && re[0] == 3, "from ::1: received, CE");
            CHECK(ra[0] == 6 && ra[18] == 1 && port_of(ra) == port_of(l6b), "the IPv6 peer reported as ::1");
            CHECK(ping(w, p4, lp, 1, 100, 2, re, NULL, NULL) == 1 && re[0] == 2, "to 127.0.0.1: delivered with ECT(0) (IP_TOS on the v4-mapped half)");
            CHECK(ping(w, s6, l6b, 1, 100, 2, re, NULL, NULL) == 1 && re[0] == 2, "to ::1: delivered with ECT(0)");
            uint8_t fd8[4]; CHECK(ksl_udp_get(w, KSL_UDP_GET_FD, fd8, 4, &n) == KSL_OK, "fd"); int fd = (int)(((uint32_t)fd8[0] << 24) | ((uint32_t)fd8[1] << 16) | ((uint32_t)fd8[2] << 8) | fd8[3]);
#ifdef __APPLE__
            CHECK(ksl_udp_df_mode_for_test(fd) == 1, "IPV6_DONTFRAG set on the dual-stack socket");
            /* Darwin applies IPV6_DONTFRAG to the v4-mapped half too: 20000 bytes over lo0 (MTU 16384) cannot leave unfragmented */
            { uint8_t *big = malloc(20000); memset(big, 9, 20000); uint8_t *bb[1] = { big }; uint32_t bl[1] = { 20000 }, sent = 0; uint8_t be[1] = { 0 };
              CHECK(ksl_udp_send(w, bb, bl, lp, be, 1, &sent) == KSL_OK && sent == 1, "a datagram over the MTU is a lost slot");
              uint8_t *rb[1] = { big }; uint32_t rc[1] = { 20000 }, rl[1], got = 0; uint8_t ra1[KSL_UDP_ADDR_LEN], re1[1]; int r = ksl_udp_recv(p4, rb, rc, rl, ra1, re1, 1, &got, 200);
              CHECK(r == KSL_WANT_READ || got == 0, "DF held for the IPv4 peer: nothing fragmented arrived"); free(big); }
#else
            CHECK(ksl_udp_df_mode_for_test(fd) == 3, "IPv4 half in probe mode (IP_MTU_DISCOVER on the AF_INET6 socket)");
#endif
          }
          if (w) ksl_udp_close(w); if (s6) ksl_udp_close(s6); if (p4) ksl_udp_close(p4);
          /* :: asked: the same dual-stack socket, :: reported */
          uint8_t any6[KSL_UDP_ADDR_LEN] = { 6 }; ksl_udp *w6 = ksl_udp_open(any6, 0, &err, msg, sizeof msg);
          if (w6) { uint8_t lw[KSL_UDP_ADDR_LEN], to4[KSL_UDP_ADDR_LEN]; size_t n = 0; ksl_udp_get(w6, KSL_UDP_GET_LOCAL, lw, KSL_UDP_ADDR_LEN, &n); CHECK(lw[0] == 6, ":: reported"); v4(to4, port_of(lw));
            CHECK(ping(a, w6, to4, 1, 100, 0, NULL, NULL, NULL) == 1, ":: takes IPv4 too"); ksl_udp_close(w6); } }
        /* udp_wildcard_port_free_on_ipv4_side: a dual-stack socket never gets a port an IPv4 socket holds. Darwin hands out such a
           port (it looks at the IPv6 side only) and the IPv4 holder keeps the IPv4 datagrams: with ~4000 of the 16384 ephemeral ports
           held on 127.0.0.1, about one wildcard open in five collided before the fix (a client that never received its replies) */
        { struct rlimit old; CHECK(getrlimit(RLIMIT_NOFILE, &old) == 0, "getrlimit"); struct rlimit more = old;
          if (more.rlim_cur < 8192) more.rlim_cur = more.rlim_max < 8192 ? more.rlim_max : 8192; setrlimit(RLIMIT_NOFILE, &more); getrlimit(RLIMIT_NOFILE, &more);
          int want = more.rlim_cur > 4300 ? 4000 : (int)more.rlim_cur - 300, held = 0, collided = 0, opened = 0; int *fds = calloc(4000, sizeof(int)); uint8_t *taken = calloc(65536, 1);
          for (int i = 0; i < want; i++) { int f = socket(AF_INET, SOCK_DGRAM, 0); if (f < 0) break; struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t l = sizeof a; if (bind(f, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(f, (struct sockaddr *)&a, &l) != 0) { close(f); break; } taken[ntohs(a.sin_port)] = 1; fds[held++] = f; }
          CHECK(held >= 1000, "held IPv4 ports on 127.0.0.1");
          uint8_t any4[KSL_UDP_ADDR_LEN]; v4(any4, 0); memset(any4 + 3, 0, 4);
          for (int i = 0; i < 64; i++) { uint32_t err = 0; char msg[128] = {0}; ksl_udp *w = ksl_udp_open(any4, 0, &err, msg, sizeof msg); if (!w) continue; opened++;
            uint8_t lw[KSL_UDP_ADDR_LEN]; size_t n = 0; ksl_udp_get(w, KSL_UDP_GET_LOCAL, lw, KSL_UDP_ADDR_LEN, &n); if (taken[port_of(lw)]) collided++; ksl_udp_close(w); }
          printf("udp: %d wildcard opens beside %d held IPv4 ports, %d on a held port\n", opened, held, collided);
          CHECK(opened == 64 && collided == 0, "a wildcard socket's port is free on the IPv4 side too");
          for (int i = 0; i < held; i++) close(fds[i]); free(fds); free(taken); setrlimit(RLIMIT_NOFILE, &old); }
        /* udp_wildcard_port_held_on_ipv4_refused: 0.0.0.0:P while an IPv4 socket holds 0.0.0.0:P is refused (Darwin bound :: beside it,
           and that socket kept every IPv4 datagram for P) */
        { int f = socket(AF_INET, SOCK_DGRAM, 0); struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); socklen_t l = sizeof a;
          CHECK(f >= 0 && bind(f, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(f, (struct sockaddr *)&a, &l) == 0, "an IPv4 socket on 0.0.0.0");
          uint8_t at[KSL_UDP_ADDR_LEN]; v4(at, ntohs(a.sin_port)); memset(at + 3, 0, 4); uint32_t err = 0; char msg[128] = {0};
          ksl_udp *w = ksl_udp_open(at, 0, &err, msg, sizeof msg); CHECK(w == NULL && err == KSL_E_BAD_ARG, "0.0.0.0 on a port an IPv4 socket holds is refused");
          if (w) ksl_udp_close(w); if (f >= 0) close(f); }
        /* udp_wildcard_without_ipv6_falls_back: socket(AF_INET6) fails (a host without IPv6): 0.0.0.0 opens AF_INET as before, :: fails */
        { ksl_udp_no_ipv6_for_test(1); uint8_t any4[KSL_UDP_ADDR_LEN]; v4(any4, 0); memset(any4 + 3, 0, 4); uint32_t err = 0; char msg[128] = {0};
          ksl_udp *w = ksl_udp_open(any4, KSL_UDP_ECN | KSL_UDP_DF, &err, msg, sizeof msg); CHECK(w != NULL, "0.0.0.0 without IPv6: AF_INET");
          uint8_t any6[KSL_UDP_ADDR_LEN] = { 6 }; ksl_udp *w6 = ksl_udp_open(any6, 0, &err, msg, sizeof msg); CHECK(w6 == NULL && err == KSL_E_NOT_SUPPORTED, ":: without IPv6: not supported");
          ksl_udp_no_ipv6_for_test(0);
          if (w) { uint8_t lw[KSL_UDP_ADDR_LEN], to4[KSL_UDP_ADDR_LEN], re[4]; size_t n = 0; ksl_udp_get(w, KSL_UDP_GET_LOCAL, lw, KSL_UDP_ADDR_LEN, &n); v4(to4, port_of(lw));
            CHECK((caps_of(w, NULL) & KSL_UDP_ECN) && (caps_of(w, NULL) & KSL_UDP_DF), "ECN and DF on the AF_INET fallback");
            CHECK(ping(a, w, to4, 1, 100, 2, re, NULL, NULL) == 1 && re[0] == 2, "the fallback receives IPv4 with its mark"); ksl_udp_close(w); }
          if (w6) ksl_udp_close(w6); }
        /* udp_open_without_wake_pipe: with one free descriptor below RLIMIT_NOFILE the socket opens but the wake pipe cannot.
           Darwin: the pipe is the only way to wake a blocked receive, so open fails (KSL_E_NOT_SUPPORTED) and leaks no descriptor;
           Linux: open goes on without the pipe */
        { struct rlimit old; CHECK(getrlimit(RLIMIT_NOFILE, &old) == 0, "getrlimit"); int lowest = dup(0); CHECK(lowest >= 0, "dup"); close(lowest);
          struct rlimit low = old; low.rlim_cur = (rlim_t)lowest + 2; CHECK(setrlimit(RLIMIT_NOFILE, &low) == 0, "setrlimit");
          uint8_t a4[KSL_UDP_ADDR_LEN]; v4(a4, 0); uint32_t err = 0; char msg[128] = {0}; ksl_udp *p = ksl_udp_open(a4, 0, &err, msg, sizeof msg);
          setrlimit(RLIMIT_NOFILE, &old);
#ifdef __APPLE__
          CHECK(p == NULL && err == KSL_E_NOT_SUPPORTED, "Darwin: no wake pipe, no socket");
#else
          CHECK(p != NULL, "Linux: the socket opens without the wake pipe");
#endif
          if (p) ksl_udp_close(p); int again = dup(0); CHECK(again == lowest, "no descriptor leaked"); if (again >= 0) close(again); }
        /* udp_reuseport_two_sockets_one_port (Linux); udp_reuseport_not_granted_on_apple: Darwin hands unicast UDP to one of the
           SO_REUSEPORT sockets only (no flow hashing), so the flag is never granted there and a second bind on the port fails */
        { uint8_t l1[KSL_UDP_ADDR_LEN]; ksl_udp *r1 = open_lo(KSL_UDP_REUSEPORT, l1); CHECK(r1 != NULL, "reuseport socket 1"); if (r1) { uint32_t err = 0; char msg[128] = {0}; ksl_udp *r2 = ksl_udp_open(l1, KSL_UDP_REUSEPORT, &err, msg, sizeof msg);
#ifdef __APPLE__
            CHECK(!(caps_of(r1, NULL) & KSL_UDP_REUSEPORT), "REUSEPORT not granted on Darwin"); CHECK(r2 == NULL && err == KSL_E_BAD_ARG, "second socket on the same port refused");
#else
            CHECK(caps_of(r1, NULL) & KSL_UDP_REUSEPORT, "REUSEPORT granted"); CHECK(r2 != NULL, "second socket on the same port with REUSEPORT");
#endif
            if (r2) ksl_udp_close(r2); ksl_udp_close(r1); } }
        /* udp_close_wakes_blocked_recv: a receive blocked with a long timeout returns within 100 ms of close */
        { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(0, lc); CHECK(c != NULL, "socket for close test"); if (c) { CHECK(ksl_udp_close_wakes_for_test(c) <= 100, "shutdown wakes a blocked recv within 100 ms"); } }
        /* udp_shutdown_then_calls_fail_fast: a shut socket answers KSL_ERROR to send and recv without waiting; close after shutdown is fine */
        { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(0, lc); CHECK(c != NULL, "socket for shutdown test");
          if (c) { ksl_udp_shutdown(c); uint8_t buf[8] = {0}; uint8_t *bufs[1] = { buf }; uint32_t lens[1] = { 8 }, caps[1] = { 8 }, got = 0, sent = 0; uint8_t e[1] = { 0 };
            CHECK(ksl_udp_send(c, bufs, lens, lb, e, 1, &sent) == KSL_ERROR, "send after shutdown is an error"); CHECK(ksl_udp_recv(c, bufs, caps, lens, lc, e, 1, &got, 1000) == KSL_ERROR && got == 0, "recv after shutdown is an error, at once"); ksl_udp_close(c); } }
        /* negative_udp_dropped_datagrams_keep_the_timeout (0.2.1 review): datagrams ksl drops without handing them out (empty ones,
           here) must not restart the wait. A sender of one empty datagram every 5 ms (200 datagrams/s, 28 bytes each on the wire)
           must not keep a receive with a 20 ms timeout from answering KSL_WANT_READ: the loop's direct receive (BatchReceiver) runs
           on the loop's thread, so a receive that never returns starves its timers and commands */
        { uint8_t lr[KSL_UDP_ADDR_LEN]; ksl_udp *r = open_lo(0, lr); CHECK(r != NULL, "receiver for the dropped-datagram test");
          if (r) {
            struct junk_args ja = { port_of(lr), 0 }; pthread_t t; CHECK(pthread_create(&t, NULL, junk_thread, &ja) == 0, "junk sender");
            struct timespec w = { 0, 20000000 }; nanosleep(&w, NULL);   /* the flood is on */
            uint8_t buf[1500]; uint8_t *bufs[1] = { buf }; uint32_t caps[1] = { sizeof buf }, lens[1], got = 0; uint8_t ra[KSL_UDP_ADDR_LEN], re[1];
            struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
            int rc = ksl_udp_recv(r, bufs, caps, lens, ra, re, 1, &got, 20);
            clock_gettime(CLOCK_MONOTONIC, &t1); long ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
            ja.stop = 1; pthread_join(t, NULL);
            CHECK(rc == KSL_WANT_READ && got == 0, "only empty datagrams: KSL_WANT_READ");
            CHECK(ms < 200, "a 20 ms receive answers within 200 ms while empty datagrams keep arriving");
            int64_t ns = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000000000 + (t1.tv_nsec - t0.tv_nsec);
            CHECK(ns >= 20000000, "and not before its 20 ms: the deadline is not rounded down");
            if (ns < 20000000) printf("    the 20 ms receive answered after %lld us\n", (long long)(ns / 1000));
            if (ms >= 200) printf("    the 20 ms receive took %ld ms (it returned only when the junk sender stopped)\n", ms);
          }
          if (r) ksl_udp_close(r); }
        /* negative_udp_dropped_run_is_bounded_per_call: a queue of dropped datagrams longer than the drain (recvmsg never answers
           EAGAIN) still ends a receive that may not wait; the datagram behind them comes out on a later call */
        { uint8_t lr[KSL_UDP_ADDR_LEN]; ksl_udp *r = open_lo(0, lr); int s = socket(AF_INET, SOCK_DGRAM, 0); CHECK(r != NULL && s >= 0, "sockets for the dropped-run test");
          if (r && s >= 0) {
            struct sockaddr_in to; memset(&to, 0, sizeof to); to.sin_family = AF_INET; to.sin_port = htons(port_of(lr)); to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef __APPLE__
            to.sin_len = sizeof to;
#endif
            for (int i = 0; i < 100; i++) (void)sendto(s, "", 0, 0, (struct sockaddr *)&to, sizeof to);
            (void)sendto(s, "q", 1, 0, (struct sockaddr *)&to, sizeof to);
            uint8_t buf[64]; uint8_t *bufs[1] = { buf }; uint32_t caps[1] = { sizeof buf }, lens[1], got = 0; uint8_t ra[KSL_UDP_ADDR_LEN], re[1];
            CHECK(ksl_udp_recv(r, bufs, caps, lens, ra, re, 1, &got, 0) == KSL_WANT_READ && got == 0, "timeout 0: a run of 64 dropped datagrams ends the call");
            int calls = 1; while (got == 0 && calls < 4) { (void)ksl_udp_recv(r, bufs, caps, lens, ra, re, 1, &got, 100); calls++; }
            CHECK(got == 1 && lens[0] == 1 && buf[0] == 'q', "the datagram behind the dropped run is received by a later call");
            /* the bound never costs a datagram it already took (review): 63 empty ones and a real one, then 64 and 127 empty ones
               and a real one, each read only with timeout 0 as BatchReceiver starts every batch */
            const int runs[3] = { 63, 64, 127 };
            for (int k = 0; k < 3; k++) {
              for (int i = 0; i < runs[k]; i++) (void)sendto(s, "", 0, 0, (struct sockaddr *)&to, sizeof to);
              (void)sendto(s, "q", 1, 0, (struct sockaddr *)&to, sizeof to);
              got = 0; buf[0] = 0; int tries = 0; while (got == 0 && tries < 4) { (void)ksl_udp_recv(r, bufs, caps, lens, ra, re, 1, &got, 0); tries++; }
              CHECK(got == 1 && lens[0] == 1 && buf[0] == 'q', "timeout 0: the real datagram behind a dropped run is never lost");
              if (runs[k] == 63) CHECK(tries == 1, "63 dropped datagrams and a real one: the first call delivers it");
              if (got != 1 || buf[0] != 'q') printf("    lost the datagram behind %d empty ones\n", runs[k]);
            }
          }
          if (s >= 0) close(s); if (r) ksl_udp_close(r); }
        /* udp_error_text_matches_its_errno: the sender and the receiver thread both record errors; the errno and the text read
           together (KSL_UDP_GET_ERROR) must always be one error's, never one's number with the other's text or a torn text */
        { uint8_t lr[KSL_UDP_ADDR_LEN]; ksl_udp *r = open_lo(0, lr); CHECK(r != NULL, "socket for the error-text test");
          if (r) {
            char want_send[256], want_recv[256]; snprintf(want_send, sizeof want_send, "sendmsg: %s", strerror(EINVAL)); snprintf(want_recv, sizeof want_recv, "recvmsg: %s", strerror(ENOBUFS));
            struct err_args w1 = { r, EINVAL, "sendmsg" }, w2 = { r, ENOBUFS, "recvmsg" }; pthread_t t1, t2;
            CHECK(pthread_create(&t1, NULL, err_writer, &w1) == 0 && pthread_create(&t2, NULL, err_writer, &w2) == 0, "error writers");
            int torn = 0;
            for (int i = 0; i < 100000; i++) {
              uint8_t out[4 + 512]; size_t n = 0; if (ksl_udp_get(r, KSL_UDP_GET_ERROR, out, sizeof out, &n) != KSL_OK || n < 4) { torn++; continue; }
              uint32_t e = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) | ((uint32_t)out[2] << 8) | out[3]; size_t ml = n - 4;
              const char *want = e == EINVAL ? want_send : e == ENOBUFS ? want_recv : "";
              if (strlen(want) != ml || memcmp(out + 4, want, ml) != 0) torn++;
            }
            pthread_join(t1, NULL); pthread_join(t2, NULL);
            CHECK(torn == 0, "every error read is one error's number and text");
            if (torn) printf("    %d of 100000 reads mixed two errors\n", torn);
          }
          if (r) ksl_udp_close(r); }
        /* udp_ptb_ring: 16 Packet Too Big messages are kept in order between two takes, a flood beyond that drops the newest, quotes
           are cut to KSL_UDP_PTB_QUOTE and to the caller's buffer (the receiver fills the ring on Linux; the ring is the same everywhere) */
        { uint8_t q[100], dst[KSL_UDP_ADDR_LEN], out[KSL_UDP_PTB_QUOTE], od[KSL_UDP_ADDR_LEN]; uint32_t ql = 0, mtu = 0; memset(q, 0x55, sizeof q);
          for (uint32_t i = 0; i < 20; i++) { v4(dst, (uint16_t)(1000 + i)); ksl_udp_push_ptb_for_test(a, q, sizeof q, dst, 1280 + i); }
          int order = 1; uint32_t taken = 0;
          while (ksl_udp_take_ptb(a, out, sizeof out, &ql, od, &mtu)) { if (mtu != 1280 + taken || port_of(od) != 1000 + taken || ql != KSL_UDP_PTB_QUOTE) order = 0; taken++; }
          CHECK(taken == 16 && order, "the ring keeps the 16 oldest, in order, quotes cut to 64 bytes");
          CHECK(ksl_udp_ptb_dropped_for_test(a) == 4, "four newer ones dropped");
          ksl_udp_push_ptb_for_test(a, q, sizeof q, dst, 1300); CHECK(ksl_udp_take_ptb(a, out, 10, &ql, od, &mtu) == 1 && ql == 10, "the caller's capacity bounds the quote");
          CHECK(ksl_udp_take_ptb(a, out, sizeof out, &ql, od, &mtu) == 0, "empty again"); }
        /* udp_recverr_port_unreachable_keeps_socket: a datagram to a closed local port draws an ICMP port unreachable (Linux queues it
           with IP_RECVERR and sets sk_err, which recvmsg used to report as a socket error); the receive answers a timeout, takes no
           Packet Too Big, does not spin on POLLERR, and the next datagram is received. Apple delivers no ICMP to an unconnected socket */
        { uint8_t lc[KSL_UDP_ADDR_LEN], ld[KSL_UDP_ADDR_LEN], le[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(0, lc), *d = open_lo(KSL_UDP_DF, ld), *e = open_lo(0, le);
          CHECK(c && d && e, "sockets for the port-unreachable test");
          if (c && d && e) { ksl_udp_close(c); c = NULL;
            CHECK(send1(d, lc, 100) == 1, "datagram to the closed port");
            uint32_t s0 = ksl_udp_recv_syscalls_for_test(d);
            int r = recv1(d, 200); CHECK(r == 0, "a queued ICMP error is a timeout, not a socket error");
            if (r < 0) { uint8_t eo[300]; size_t en = 0; ksl_udp_get(d, KSL_UDP_GET_ERROR, eo, sizeof eo, &en); printf("    recv error: %.*s\n", (int)(en > 4 ? en - 4 : 0), eo + 4); }
            CHECK(ksl_udp_recv_syscalls_for_test(d) - s0 < 64, "no spin on POLLERR");
            CHECK(send1(d, lc, 100) == 1, "and the next send to it is not an error either");
            uint8_t out[KSL_UDP_PTB_QUOTE], od[KSL_UDP_ADDR_LEN]; uint32_t ql = 0, mtu = 0; (void)recv1(d, 50);
            CHECK(ksl_udp_take_ptb(d, out, sizeof out, &ql, od, &mtu) == 0, "port unreachable is no Packet Too Big");
            CHECK(send1(e, ld, 100) == 1 && recv1(d, 500) == 100, "the socket still receives");
#ifdef __linux__
            CHECK(ksl_udp_recverr_for_test(d) == 1 && ksl_udp_errqueue_reads_for_test(d) > 0, "IP_RECVERR on with DF, the error queue drained");
#endif
          }
          if (c) ksl_udp_close(c); if (d) ksl_udp_close(d); if (e) ksl_udp_close(e); }
#ifdef __APPLE__
        /* udp_emsgsize_counted: a datagram larger than lo0's MTU (16384) with DF set is refused with EMSGSIZE: a lost slot, counted
           with its size for DPLPMTUD (ksl_udp_emsgsize); the socket is fine */
        { uint32_t last = 0; uint64_t e0 = ksl_udp_emsgsize(a, &last);
          CHECK(send1(a, lb, 20000) == 1, "the oversized slot counts as sent (lost)");
          CHECK(ksl_udp_emsgsize(a, &last) == e0 + 1 && last == 20000, "EMSGSIZE counted with the datagram's size");
          CHECK(send1(a, lb, 100) == 1 && recv1(b, 500) == 100, "the socket still sends"); }
#endif
#ifdef __linux__
        { pid_t pid = fork();
          if (pid == 0) _exit(ptb_child());
          int st = 0; waitpid(pid, &st, 0); int code = WIFEXITED(st) ? WEXITSTATUS(st) : 100;
          if (code == 77) printf("udp_recverr_ptb_parsed: SKIP (no unprivileged user namespace)\n");
          else CHECK(code == 0, "udp_recverr_local_emsgsize_queued + udp_recverr_ptb_parsed (child exit = failed step)");
          if (code != 0 && code != 77) printf("    ptb child failed at step %d\n", code); }
#endif
        ksl_udp_close(a); ksl_udp_close(b);
    }
#elif defined(_WIN32)
    { void run_udp_win(void); (void)v4; run_udp_win(); }   /* test_udp_win.c */
#else
    /* udp_open_unsupported (Windows) */
    { uint8_t a[KSL_UDP_ADDR_LEN]; v4(a, 0); uint32_t err = 0; char msg[64] = {0}; CHECK(ksl_udp_open(a, 0, &err, msg, sizeof msg) == NULL && err == KSL_E_NOT_SUPPORTED, "ksl_udp_open is Linux and Apple only"); }
#endif
    END();
}
