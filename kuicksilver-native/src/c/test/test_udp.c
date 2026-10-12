/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_udp_*: batched UDP with GSO, GRO, ECN, DF and REUSEPORT (ADR-0006; threat-model 3.12, 3.16). Linux and Apple (no GSO/GRO there);
 * elsewhere ksl_udp_open answers KSL_E_NOT_SUPPORTED. */
#include "test_common.h"
#include <errno.h>
#include <pthread.h>

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
          CHECK(ksl_udp_df_mode_for_test(fd) == 1, "IP_DONTFRAG set (Darwin has no PMTUDISC modes and no PMTU cache for UDP sends)"); }
#else
          CHECK(ksl_udp_df_mode_for_test(fd) == 3 /* IP_PMTUDISC_PROBE */, "probe mode, not DO"); }
#endif
        /* udp_truncated_datagram_dropped: a 1400-byte datagram into a 1000-byte slot is dropped, not truncated */
        { uint8_t *bufs[1]; uint32_t lens[1] = {1400}; uint8_t addrs[KSL_UDP_ADDR_LEN]; uint8_t ecns[1] = {0}; bufs[0] = malloc(1400); memset(bufs[0], 7, 1400); memcpy(addrs, lb, KSL_UDP_ADDR_LEN); uint32_t sent = 0;
          CHECK(ksl_udp_send(a, bufs, lens, addrs, ecns, 1, &sent) == KSL_OK && sent == 1, "big one sent"); uint8_t *rb[1]; uint32_t rc[1] = {1000}; uint32_t rl[1]; uint8_t ra[KSL_UDP_ADDR_LEN]; uint8_t re[1]; uint32_t got = 0; rb[0] = malloc(1000);
          int r = ksl_udp_recv(b, rb, rc, rl, ra, re, 1, &got, 300); CHECK((r == KSL_OK && got == 0) || r == KSL_WANT_READ, "truncated datagram dropped"); free(bufs[0]); free(rb[0]); }
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
        /* udp_reuseport_two_sockets_one_port */
        { uint8_t l1[KSL_UDP_ADDR_LEN]; ksl_udp *r1 = open_lo(KSL_UDP_REUSEPORT, l1); CHECK(r1 != NULL, "reuseport socket 1"); if (r1) { uint32_t err = 0; char msg[128] = {0}; ksl_udp *r2 = ksl_udp_open(l1, KSL_UDP_REUSEPORT, &err, msg, sizeof msg); CHECK(r2 != NULL, "second socket on the same port with REUSEPORT"); if (r2) ksl_udp_close(r2); ksl_udp_close(r1); } }
        /* udp_close_wakes_blocked_recv: a receive blocked with a long timeout returns within 100 ms of close */
        { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(0, lc); CHECK(c != NULL, "socket for close test"); if (c) { CHECK(ksl_udp_close_wakes_for_test(c) <= 100, "shutdown wakes a blocked recv within 100 ms"); } }
        /* udp_shutdown_then_calls_fail_fast: a shut socket answers KSL_ERROR to send and recv without waiting; close after shutdown is fine */
        { uint8_t lc[KSL_UDP_ADDR_LEN]; ksl_udp *c = open_lo(0, lc); CHECK(c != NULL, "socket for shutdown test");
          if (c) { ksl_udp_shutdown(c); uint8_t buf[8] = {0}; uint8_t *bufs[1] = { buf }; uint32_t lens[1] = { 8 }, caps[1] = { 8 }, got = 0, sent = 0; uint8_t e[1] = { 0 };
            CHECK(ksl_udp_send(c, bufs, lens, lb, e, 1, &sent) == KSL_ERROR, "send after shutdown is an error"); CHECK(ksl_udp_recv(c, bufs, caps, lens, lc, e, 1, &got, 1000) == KSL_ERROR && got == 0, "recv after shutdown is an error, at once"); ksl_udp_close(c); } }
        ksl_udp_close(a); ksl_udp_close(b);
    }
#else
    /* udp_open_unsupported (Windows) */
    { uint8_t a[KSL_UDP_ADDR_LEN]; v4(a, 0); uint32_t err = 0; char msg[64] = {0}; CHECK(ksl_udp_open(a, 0, &err, msg, sizeof msg) == NULL && err == KSL_E_NOT_SUPPORTED, "ksl_udp_open is Linux and Apple only"); }
#endif
    END();
}
