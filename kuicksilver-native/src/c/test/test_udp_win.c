/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_udp_* on Windows (ksl_udp_win.c, ADR-0006): batches over WSASendMsg/WSARecvMsg, USO/URO and ECN where the system grants
 * them, DF, dual-stack, exclusive bind, the wake socket. Called from run_udp (test_udp.c) on _WIN32 only. */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "test_common.h"
#include <windows.h>

int ksl_udp_has_wake_for_test(ksl_udp *); void ksl_udp_fail_next_recv_for_test(ksl_udp *, int err); void ksl_udp_fake_pollerr_for_test(ksl_udp *, int on); uint32_t ksl_udp_polls_for_test(ksl_udp *);
uint32_t ksl_udp_split_for_test(ksl_udp *, const uint8_t *train, uint32_t len, uint32_t seg, uint8_t mark, uint16_t port, uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecnv, uint32_t n);

#define W_WSAEOPNOTSUPP 10045
#define W_WSAENETUNREACH 10051
#define W_WSAENOBUFS 10055
#define W_WSAENETDOWN 10050

static void w4(uint8_t a[KSL_UDP_ADDR_LEN], uint16_t port) { memset(a, 0, KSL_UDP_ADDR_LEN); a[0] = 4; a[1] = (uint8_t)(port >> 8); a[2] = (uint8_t)port; a[3] = 127; a[6] = 1; }
/* a plain Winsock socket with SO_REUSEADDR on 127.0.0.1:port: 1 when its bind is refused */
static int raw_reuseaddr_bind_fails(const uint8_t a[KSL_UDP_ADDR_LEN]) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if (s == INVALID_SOCKET) { printf("raw socket: %d\n", WSAGetLastError()); return 0; }
    BOOL yes = TRUE; if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof yes) != 0) { printf("SO_REUSEADDR: %d\n", WSAGetLastError()); closesocket(s); return 0; }
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; memcpy(&sa.sin_port, a + 1, 2); memcpy(&sa.sin_addr, a + 3, 4);
    int r = bind(s, (struct sockaddr *)&sa, sizeof sa); closesocket(s); return r != 0;
}
static uint16_t wport(const uint8_t a[KSL_UDP_ADDR_LEN]) { return (uint16_t)((a[1] << 8) | a[2]); }
static ksl_udp *wopen(const uint8_t at[KSL_UDP_ADDR_LEN], int flags, uint8_t local[KSL_UDP_ADDR_LEN]) {
    uint32_t err = 0; char msg[128] = {0}; ksl_udp *u = ksl_udp_open(at, flags, &err, msg, sizeof msg); if (!u) { printf("open: %u %s\n", err, msg); return NULL; }
    size_t n = 0; CHECK(ksl_udp_get(u, KSL_UDP_GET_LOCAL, local, KSL_UDP_ADDR_LEN, &n) == KSL_OK && n == KSL_UDP_ADDR_LEN, "local address"); return u;
}
static ksl_udp *wopen_lo(int flags, uint8_t local[KSL_UDP_ADDR_LEN]) { uint8_t a[KSL_UDP_ADDR_LEN]; w4(a, 0); return wopen(a, flags, local); }
static uint32_t wcaps(ksl_udp *u, uint16_t *gso_max) { uint8_t c[8]; size_t n = 0; CHECK(ksl_udp_get(u, KSL_UDP_GET_CAPS, c, 8, &n) == KSL_OK && n == 8, "caps"); if (gso_max) *gso_max = (uint16_t)((c[4] << 8) | c[5]); return ((uint32_t)c[0] << 24) | ((uint32_t)c[1] << 16) | ((uint32_t)c[2] << 8) | c[3]; }
/* n datagrams of len bytes from a to `to`, received on b (up to 64); returns the count received */
static uint32_t wping(ksl_udp *a, ksl_udp *b, const uint8_t to[KSL_UDP_ADDR_LEN], uint32_t n, uint32_t len, uint8_t ecn, uint8_t *recv_ecn, uint8_t *recv_addr, uint32_t *recv_lens) {
    uint8_t *bufs[64]; uint32_t lens[64]; uint8_t addrs[64 * KSL_UDP_ADDR_LEN]; uint8_t ecns[64];
    for (uint32_t i = 0; i < n; i++) { bufs[i] = malloc(len); memset(bufs[i], (int)i, len); lens[i] = len; memcpy(addrs + i * KSL_UDP_ADDR_LEN, to, KSL_UDP_ADDR_LEN); ecns[i] = ecn; }
    uint32_t sent = 0; CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, n, &sent) == KSL_OK && sent == n, "send batch");
    uint8_t *rb[64]; uint32_t rc[64], rl[64], got = 0, total = 0; uint8_t ra[64 * KSL_UDP_ADDR_LEN], re[64];
    for (uint32_t i = 0; i < 64; i++) { rb[i] = malloc(1500); rc[i] = 1500; }
    for (int t = 0; t < 50 && total < n; t++) { int r = ksl_udp_recv(b, rb + total, rc + total, rl + total, ra + total * KSL_UDP_ADDR_LEN, re + total, 64 - total, &got, 200); if (r == KSL_WANT_READ) continue; CHECK(r == KSL_OK, "recv"); total += got; }
    for (uint32_t i = 0; i < total && i < n; i++) { if (recv_lens) recv_lens[i] = rl[i]; if (recv_ecn) recv_ecn[i] = re[i]; if (recv_addr) memcpy(recv_addr + i * KSL_UDP_ADDR_LEN, ra + i * KSL_UDP_ADDR_LEN, KSL_UDP_ADDR_LEN); }
    for (uint32_t i = 0; i < n; i++) free(bufs[i]); for (uint32_t i = 0; i < 64; i++) free(rb[i]);
    return total;
}
static uint32_t wdrain(ksl_udp *b, uint32_t *lens, uint8_t *ecns, uint32_t max) {
    uint8_t *rb[8]; uint32_t rc[8], rl[8], got = 0, total = 0; uint8_t ra[8 * KSL_UDP_ADDR_LEN], re[8]; for (int i = 0; i < 8; i++) { rb[i] = malloc(1500); rc[i] = 1500; }
    for (int t = 0; t < 20; t++) { if (ksl_udp_recv(b, rb, rc, rl, ra, re, 8, &got, 100) != KSL_OK) break; for (uint32_t i = 0; i < got; i++) { if (total < max) { if (lens) lens[total] = rl[i]; if (ecns) ecns[total] = re[i]; } total++; } }
    for (int i = 0; i < 8; i++) free(rb[i]); return total;
}

void run_udp_win(void) {
    uint8_t la[KSL_UDP_ADDR_LEN], lb[KSL_UDP_ADDR_LEN];
    ksl_udp *a = wopen_lo(KSL_UDP_ECN | KSL_UDP_GSO | KSL_UDP_GRO | KSL_UDP_DF | KSL_UDP_REUSEPORT, la), *b = wopen_lo(KSL_UDP_ECN | KSL_UDP_GSO | KSL_UDP_GRO | KSL_UDP_DF, lb);
    CHECK(a && b, "udp_open on loopback (Windows)");
    if (!a || !b) { if (a) ksl_udp_close(a); if (b) ksl_udp_close(b); return; }
    uint16_t gso_max = 0; uint32_t caps = wcaps(a, &gso_max);
    printf("udp(win): granted ECN=%d USO=%d URO=%d DF=%d\n", !!(caps & KSL_UDP_ECN), !!(caps & KSL_UDP_GSO), !!(caps & KSL_UDP_GRO), !!(caps & KSL_UDP_DF));
    CHECK(caps & KSL_UDP_DF, "DF granted (IP_DONTFRAGMENT)"); CHECK(!(caps & KSL_UDP_REUSEPORT), "REUSEPORT never granted on Windows (exclusive bind)");
    CHECK((caps & KSL_UDP_GSO) ? gso_max >= 2 : 1, "USO max segments when granted");
    /* udp_win_batch_send_recv: 32 datagrams of distinct lengths, each with the sender's address */
    { uint8_t *bufs[32]; uint32_t lens[32]; uint8_t addrs[32 * KSL_UDP_ADDR_LEN]; uint8_t ecns[32];
      for (uint32_t i = 0; i < 32; i++) { lens[i] = 100 + i * 37; bufs[i] = malloc(lens[i]); memset(bufs[i], (int)i, lens[i]); memcpy(addrs + i * KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN); ecns[i] = 0; }
      uint32_t sent = 0; CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 32, &sent) == KSL_OK && sent == 32, "32 sent");
      uint8_t *rb[64]; uint32_t rc[64], rl[64], total = 0, got; uint8_t ra[64 * KSL_UDP_ADDR_LEN], re[64]; for (int i = 0; i < 64; i++) { rb[i] = malloc(1500); rc[i] = 1500; }
      for (int t = 0; t < 50 && total < 32; t++) { int r = ksl_udp_recv(b, rb + total, rc + total, rl + total, ra + total * KSL_UDP_ADDR_LEN, re + total, 64 - total, &got, 200); if (r == KSL_WANT_READ) continue; CHECK(r == KSL_OK, "recv batch"); total += got; }
      CHECK(total == 32, "32 received"); int ok = 1;
      for (uint32_t i = 0; i < total; i++) { if ((rl[i] - 100) % 37 != 0 || rb[i][0] != (uint8_t)((rl[i] - 100) / 37) || wport(ra + i * KSL_UDP_ADDR_LEN) != wport(la) || ra[i * KSL_UDP_ADDR_LEN] != 4) ok = 0; }
      CHECK(ok, "lengths, family-4 source address and payloads match");
      for (uint32_t i = 0; i < 32; i++) free(bufs[i]); for (int i = 0; i < 64; i++) free(rb[i]); }
    /* udp_win_uso_one_call: 8 x 1200 to one address leave in one WSASendMsg with UDP_SEND_MSG_SIZE where USO is granted; 8 arrive either way */
    { uint32_t rl[64]; uint32_t before = ksl_udp_syscalls_for_test(a); uint32_t got = wping(a, b, lb, 8, 1200, 0, NULL, NULL, rl); CHECK(got == 8, "8 segments delivered");
      int ok = 1; for (uint32_t i = 0; i < got; i++) if (rl[i] != 1200) ok = 0; CHECK(ok, "segments are 1200 each");
      if (caps & KSL_UDP_GSO) CHECK(ksl_udp_syscalls_for_test(a) - before == 1, "one WSASendMsg for the run (USO)"); else CHECK(ksl_udp_syscalls_for_test(a) - before == 8, "one WSASendMsg per datagram without USO"); }
    /* udp_win_two_senders_not_merged: each sender's datagrams keep their own source address (threat-model 3.12) */
    { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = wopen_lo(KSL_UDP_GSO, lc); CHECK(c != NULL, "third socket");
      if (c) { uint8_t ra[64 * KSL_UDP_ADDR_LEN], rc2[64 * KSL_UDP_ADDR_LEN]; uint32_t rl[64]; uint32_t g1 = wping(a, b, lb, 4, 1200, 0, NULL, ra, rl), g2 = wping(c, b, lb, 4, 1200, 0, NULL, rc2, rl);
        int ok = g1 == 4 && g2 == 4; for (uint32_t i = 0; i < g1; i++) if (wport(ra + i * KSL_UDP_ADDR_LEN) != wport(la)) ok = 0; for (uint32_t i = 0; i < g2; i++) if (wport(rc2 + i * KSL_UDP_ADDR_LEN) != wport(lc)) ok = 0;
        CHECK(ok, "each sender's datagrams carry its own address"); ksl_udp_close(c); } }
    /* udp_win_ecn_roundtrip: ECT(0) and CE arrive where ECN is granted (Windows 10 2004+ / Server 2022) */
    if (caps & KSL_UDP_ECN) { uint8_t re[64]; uint32_t got = wping(a, b, lb, 2, 100, 2, re, NULL, NULL); CHECK(got == 2 && re[0] == 2 && re[1] == 2, "ECT(0) arrives"); got = wping(a, b, lb, 1, 100, 3, re, NULL, NULL); CHECK(got == 1 && re[0] == 3, "CE arrives"); }
    else printf("udp(win): ECN not granted by this Windows, ECN roundtrip skipped\n");
    /* udp_win_df_probe_mode: IP_MTU_DISCOVER is PROBE where the system has the option, never DO */
    { uint8_t fd8[4]; size_t n = 0; CHECK(ksl_udp_get(a, KSL_UDP_GET_FD, fd8, 4, &n) == KSL_OK && n == 4, "fd"); int fd = (int)(((uint32_t)fd8[0] << 24) | ((uint32_t)fd8[1] << 16) | ((uint32_t)fd8[2] << 8) | fd8[3]);
      int mode = ksl_udp_df_mode_for_test(fd); CHECK(mode == 3, "IP_MTU_DISCOVER reads back PROBE (3); -1 (getsockopt failed) is a failure, never DO"); }
    /* udp_win_truncated_datagram_dropped: 1400 bytes into a 1000-byte slot are dropped, not truncated */
    { uint8_t *bufs[1]; uint32_t lens[1] = { 1400 }; uint8_t ecns[1] = { 0 }; bufs[0] = malloc(1400); memset(bufs[0], 7, 1400); uint32_t sent = 0;
      CHECK(ksl_udp_send(a, bufs, lens, lb, ecns, 1, &sent) == KSL_OK && sent == 1, "big one sent");
      uint8_t *rb[1]; uint32_t rc[1] = { 1000 }, rl[1], got = 0; uint8_t ra[KSL_UDP_ADDR_LEN], re[1]; rb[0] = malloc(1000);
      int r = ksl_udp_recv(b, rb, rc, rl, ra, re, 1, &got, 300); CHECK((r == KSL_OK && got == 0) || r == KSL_WANT_READ, "truncated datagram dropped"); free(bufs[0]); free(rb[0]); }
    /* udp_win_uso_transient_error_keeps_uso: WSAENOBUFS on a USO send resends that run one by one and leaves USO on */
    if (wcaps(a, NULL) & KSL_UDP_GSO) { uint32_t rl[64]; uint32_t before = ksl_udp_syscalls_for_test(a); ksl_udp_fail_next_gso_for_test(a, W_WSAENOBUFS);
      CHECK(wping(a, b, lb, 6, 1000, 0, NULL, NULL, rl) == 6, "WSAENOBUFS on USO: all six delivered one by one");
      CHECK(ksl_udp_syscalls_for_test(a) - before == 7, "the refused USO call, then six single sends");
      CHECK(wcaps(a, NULL) & KSL_UDP_GSO, "USO still granted after a transient error");
      before = ksl_udp_syscalls_for_test(a); CHECK(wping(a, b, lb, 6, 1000, 0, NULL, NULL, rl) == 6 && ksl_udp_syscalls_for_test(a) - before == 1, "the next run leaves in one USO call"); }
    /* udp_win_uso_refused_falls_back: WSAEOPNOTSUPP on a USO send turns USO off and resends every segment one by one */
    if (caps & KSL_UDP_GSO) { ksl_udp_fail_next_gso_for_test(a, W_WSAEOPNOTSUPP); uint32_t rl[64]; CHECK(wping(a, b, lb, 6, 1000, 0, NULL, NULL, rl) == 6, "all six delivered after the fallback"); CHECK(!(wcaps(a, NULL) & KSL_UDP_GSO), "USO withdrawn from the caps"); }
    /* udp_win_transient_error_skips_the_slot: WSAENETUNREACH loses that datagram only */
    { uint8_t *bufs[2]; uint32_t lens[2] = { 100, 90 }; uint8_t addrs[2 * KSL_UDP_ADDR_LEN]; uint8_t ecns[2] = { 0, 0 }; for (int i = 0; i < 2; i++) { bufs[i] = malloc(100); memset(bufs[i], 0x60 + i, 100); memcpy(addrs + i * KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN); }
      uint32_t sent = 0; ksl_udp_fail_next_send_for_test(a, W_WSAENETUNREACH); CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "WSAENETUNREACH: the slot is given up, the socket lives");
      CHECK(wdrain(b, NULL, NULL, 0) == 1, "the other datagram reached the wire"); for (int i = 0; i < 2; i++) free(bufs[i]); }
    /* udp_win_bad_destination_keeps_ecn: port 0 is the destination's fault; the valid slot behind it still leaves marked */
    { uint8_t zero[KSL_UDP_ADDR_LEN]; w4(zero, 0); uint8_t *bufs[2]; uint32_t lens[2] = { 100, 90 }; uint8_t addrs[2 * KSL_UDP_ADDR_LEN]; uint8_t ecns[2] = { 2, 2 }; uint32_t sent = 0;
      for (int i = 0; i < 2; i++) { bufs[i] = malloc(100); memset(bufs[i], 0x30 + i, 100); } memcpy(addrs, zero, KSL_UDP_ADDR_LEN); memcpy(addrs + KSL_UDP_ADDR_LEN, lb, KSL_UDP_ADDR_LEN);
      uint32_t before = wcaps(a, NULL) & KSL_UDP_ECN;
      CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 2, &sent) == KSL_OK && sent == 2, "[port 0, valid]: the first is lost, both counted, no socket error");
      CHECK((wcaps(a, NULL) & KSL_UDP_ECN) == before, "ECN kept after an error caused by the destination");
      uint32_t rl[4]; uint8_t re[4]; CHECK(wdrain(b, rl, re, 4) == 1 && rl[0] == 90 && (!before || re[0] == 2), "the valid slot arrived once, still marked where ECN is on");
      for (int i = 0; i < 2; i++) free(bufs[i]); }
    /* udp_win_uro_split: a synthetic 3000-byte train with UDP_COALESCED_INFO = 1200 splits into 1200, 1200, 600 with the source and
       the mark on each; a second train's slot too small for its segment drops that segment only; leftovers wait for the next call */
    { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = wopen_lo(0, lc); CHECK(c != NULL, "socket for the splitter");
      if (c) { static uint8_t train[3000]; for (int i = 0; i < 3000; i++) train[i] = (uint8_t)(i / 1200 + 1);
        uint8_t s0[1500], s1[1500], s2[1500]; uint8_t *sb[3] = { s0, s1, s2 }; uint32_t sc[3] = { 1500, 1500, 1500 }, sl[3] = { 0 }; uint8_t sa[3 * KSL_UDP_ADDR_LEN], se[3] = { 0 };
        uint32_t got = ksl_udp_split_for_test(c, train, 3000, 1200, 2, 4433, sb, sc, sl, sa, se, 2);
        CHECK(got == 2 && sl[0] == 1200 && sl[1] == 1200 && s0[0] == 1 && s0[1199] == 1 && s1[0] == 2 && s1[1199] == 2, "two slots: the first two 1200-byte segments, in order");
        CHECK(sa[0] == 4 && wport(sa) == 4433 && sa[3] == 127 && sa[6] == 1 && wport(sa + KSL_UDP_ADDR_LEN) == 4433 && se[0] == 2 && se[1] == 2, "each segment carries the source and the ECN mark");
        got = ksl_udp_split_for_test(c, NULL, 0, 0, 0, 0, sb, sc, sl, sa, se, 3);
        CHECK(got == 1 && sl[0] == 600 && s0[0] == 3 && s0[599] == 3, "the 600-byte tail waited for the next call");
        uint32_t small[3] = { 1000, 1500, 1500 }; got = ksl_udp_split_for_test(c, train, 3000, 1200, 0, 4433, sb, small, sl, sa, se, 3);
        CHECK(got == 1 && sl[0] == 600 && s0[0] == 3, "segments larger than the slot are dropped; the tail that fits takes it");
        got = ksl_udp_split_for_test(c, train, 1000, 0, 0, 4433, sb, sc, sl, sa, se, 3);
        CHECK(got == 1 && sl[0] == 1000, "no UDP_COALESCED_INFO: one datagram");
        ksl_udp_close(c); } }
    /* udp_win_recv_transient_error: WSAENETDOWN on a receive is a slice without data, not a socket error; the socket keeps working */
    { uint8_t *rb[1]; uint8_t r0[1500]; rb[0] = r0; uint32_t rc[1] = { 1500 }, rl[1], got = 9; uint8_t ra[KSL_UDP_ADDR_LEN], re[1];
      uint8_t *sb1[1] = { r0 }; uint32_t sl1[1] = { 100 }, sent = 0; uint8_t se1[1] = { 0 }; memset(r0, 5, 100);
      CHECK(ksl_udp_send(a, sb1, sl1, lb, se1, 1, &sent) == KSL_OK && sent == 1, "one datagram pending, so the receive reaches WSARecvMsg");
      ksl_udp_fail_next_recv_for_test(b, W_WSAENETDOWN); int r = ksl_udp_recv(b, rb, rc, rl, ra, re, 1, &got, 200);
      CHECK(r == KSL_WANT_READ && got == 0, "WSAENETDOWN: nothing received this slice, no KSL_ERROR");
      uint32_t l2[4]; CHECK(wdrain(b, l2, NULL, 4) == 1 && l2[0] == 100, "the pending datagram still arrives after WSAENETDOWN"); }
    /* udp_win_pollerr_does_not_spin: a socket that keeps reporting POLLERR with no SO_ERROR pending idles the slice */
    { uint8_t *rb[1]; uint8_t r0[1500]; rb[0] = r0; uint32_t rc[1] = { 1500 }, rl[1], got = 9; uint8_t ra[KSL_UDP_ADDR_LEN], re[1];
      uint32_t before = ksl_udp_polls_for_test(b); ksl_udp_fake_pollerr_for_test(b, 1); int r = ksl_udp_recv(b, rb, rc, rl, ra, re, 1, &got, 200); ksl_udp_fake_pollerr_for_test(b, 0);
      uint32_t polls = ksl_udp_polls_for_test(b) - before;
      CHECK(r == KSL_WANT_READ && got == 0, "POLLERR without a pending error: a timeout, not KSL_ERROR");
      CHECK(polls <= 10, "POLLERR idles in 50 ms slices instead of spinning"); if (polls > 10) printf("udp(win): %u polls in 200 ms\n", polls); }
    /* udp_win_dual_stack: an IPv6 socket on [::] takes IPv4 traffic and reports and answers the peer as family 4 */
    { uint8_t any6[KSL_UDP_ADDR_LEN] = { 6 }, l6[KSL_UDP_ADDR_LEN]; ksl_udp *d = wopen(any6, KSL_UDP_ECN, l6);
      if (!d) printf("udp(win): no IPv6 stack, dual-stack case skipped\n");
      else { uint8_t to[KSL_UDP_ADDR_LEN]; w4(to, wport(l6)); uint8_t ra[64 * KSL_UDP_ADDR_LEN]; uint32_t rl[64];
        CHECK(l6[0] == 6, "the dual-stack socket reports family 6 locally");
        CHECK(wping(a, d, to, 2, 200, 0, NULL, ra, rl) == 2 && ra[0] == 4 && wport(ra) == wport(la) && ra[3] == 127 && ra[6] == 1, "v4 peer reported as 127.0.0.1, family 4");
        CHECK(wping(d, a, la, 1, 150, 0, NULL, NULL, rl) == 1 && rl[0] == 150, "a family-4 destination leaves through the IPv6 socket (v4-mapped)");
        ksl_udp_close(d); } }
    /* udp_win_exclusive_bind: a second socket on a bound port is refused (SO_EXCLUSIVEADDRUSE), REUSEPORT or not */
    { uint32_t err = 0; char msg[128] = {0}; ksl_udp *r2 = ksl_udp_open(la, KSL_UDP_REUSEPORT, &err, msg, sizeof msg); CHECK(r2 == NULL && err == KSL_E_BAD_ARG, "no second socket on the same port"); if (r2) ksl_udp_close(r2);
      /* a foreign socket asking for SO_REUSEADDR: without SO_EXCLUSIVEADDRUSE on ours, Windows would let it bind the same port */
      CHECK(raw_reuseaddr_bind_fails(la), "a raw SO_REUSEADDR socket cannot bind the exclusive port"); }
    /* udp_win_close_wakes_blocked_recv: the wake socket ends a 5 s receive within 100 ms of shutdown */
    { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = wopen_lo(0, lc); CHECK(c != NULL, "socket for close test");
      if (c) { CHECK(ksl_udp_has_wake_for_test(c), "the wake socket exists (else the 50 ms slice, not the wake-up, would pass the timing)"); CHECK(ksl_udp_close_wakes_for_test(c) <= 100, "shutdown wakes a blocked recv within 100 ms"); } }
    /* udp_win_shutdown_then_calls_fail_fast */
    { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = wopen_lo(0, lc); CHECK(c != NULL, "socket for shutdown test");
      if (c) { ksl_udp_shutdown(c); uint8_t buf[8] = {0}; uint8_t *bufs[1] = { buf }; uint32_t lens[1] = { 8 }, rc[1] = { 8 }, got = 0, sent = 0; uint8_t e[1] = { 0 };
        CHECK(ksl_udp_send(c, bufs, lens, lb, e, 1, &sent) == KSL_ERROR, "send after shutdown is an error"); CHECK(ksl_udp_recv(c, bufs, rc, lens, lc, e, 1, &got, 1000) == KSL_ERROR && got == 0, "recv after shutdown is an error, at once"); ksl_udp_close(c); } }
    ksl_udp_close(a); ksl_udp_close(b);
}
#else
typedef int test_udp_win_empty_unit;   /* ISO C: a translation unit declares something */
#endif
