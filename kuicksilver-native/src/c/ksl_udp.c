/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Accelerated UDP for Linux and Apple (ADR-0006; threat-model 3.12, 3.16): one socket, batched sendmsg with UDP_SEGMENT,
 * recvmsg with UDP_GRO split into the caller's slots inside C, ECN through IP_TOS / IP_RECVTOS, DF in PROBE mode (never DO),
 * SO_REUSEPORT. A wildcard address (0.0.0.0 or ::) opens one dual-stack AF_INET6 socket on :: (IPV6_V6ONLY off), v4-mapped peers
 * reported as IPv4, as NIO and ksl_udp_win.c do; a specific address keeps its own family; 0.0.0.0 whose dual-stack socket gets no
 * DF for a lasting reason is an AF_INET socket with DF instead (KSL_UDP_V4_ONLY). Apple: the same socket without GSO/GRO (a batch is a loop of sendmsg), DF through IP_DONTFRAG/IPV6_DONTFRAG
 * (Darwin has no PMTUDISC modes), pipe + fcntl instead of pipe2. No allocation after open; errors stay in the object.
 * Other platforms (Windows): KSL_E_NOT_SUPPORTED.
 * The socket's life (open, get, shutdown, close) lives here, sending in ksl_udp_send.c, receiving in ksl_udp_recv.c. */
#include "ksl_udp_internal.h"

#ifdef KSL_UDP_ACCEL
#ifndef __linux__ /* Darwin has neither SOCK_CLOEXEC/SOCK_NONBLOCK nor pipe2 */
static int cloexec_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0)
        return -1;
    int fd_fl = fcntl(fd, F_GETFD);
    return fd_fl < 0 || fcntl(fd, F_SETFD, fd_fl | FD_CLOEXEC) != 0 ? -1 : 0;
}
#endif
static void be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
static void be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

#ifdef KSL_TEST
static int
    no_ipv6_for_test; /* simulates a host without IPv6: socket(AF_INET6) fails, 1 with EAFNOSUPPORT, else with that errno */
void ksl_udp_no_ipv6_for_test(int on) {
    no_ipv6_for_test = on;
}
/* the seams of the 0.0.0.0 DF fallback, as ksl_udp_win.c has them: */
/* the system refuses DF on the v4-mapped half of a dual-stack socket, for good (Linux: IP_MTU_DISCOVER refused there; Darwin:
   IPV6_DONTFRAG not applied to v4-mapped traffic) */
static int no_df_v4_mapped_for_test;
void ksl_udp_no_df_v4_mapped_for_test(int on) {
    no_df_v4_mapped_for_test = on;
}
static int no_df_v6_for_test; /* the system refuses DF on the IPv6 half of any AF_INET6 socket, for good */
void ksl_udp_no_df_v6_for_test(int on) {
    no_df_v6_for_test = on;
}
static int no_df_inet_for_test; /* the system refuses DF on an AF_INET socket, for good */
void ksl_udp_no_df_inet_for_test(int on) {
    no_df_inet_for_test = on;
}
static int transient_df_inet_for_test; /* a transient refusal (ENOBUFS) of DF on an AF_INET socket */
void ksl_udp_transient_df_inet_for_test(int on) {
    transient_df_inet_for_test = on;
}
static int
    no_inet_for_test; /* socket(AF_INET) fails: 1 with EAFNOSUPPORT (no IPv4 here), another value with that errno */
void ksl_udp_no_inet_for_test(int on) {
    no_inet_for_test = on;
}
static int
    split_port_for_test; /* the port the first try of a port-0 split takes, as if the kernel had given it to the IPv6 half */
void ksl_udp_split_port_for_test(int port) {
    split_port_for_test = port;
}
static uint32_t split_retries_for_test; /* port-0 splits that gave a port up because IPv4 holds it (open_split) */
uint32_t ksl_udp_split_retries_for_test(void) {
    return __atomic_load_n(&split_retries_for_test, __ATOMIC_RELAXED);
}
#endif
#ifdef __APPLE__
/* Binds an AF_INET socket to 0.0.0.0:[port] (0: any) and releases it at once: the port it got, 0 when the IPv4 side refused
   (errno set, EADDRINUSE when an IPv4 socket holds the port). */
static uint16_t ipv4_port_probe(uint16_t port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_len = sizeof a;
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    socklen_t l = sizeof a;
    uint16_t p = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(s, (struct sockaddr *)&a, &l) == 0)
        p = ntohs(a.sin_port);
    int e = errno;
    close(s);
    errno = e;
    return p;
}
/* Darwin binds a dual-stack socket without looking at the IPv4 sockets: the ephemeral port can be one an IPv4 socket holds
   (127.0.0.1:P, 0.0.0.0:P), and an explicit :: on P succeeds beside 0.0.0.0:P; either way the IPv4 socket keeps receiving the IPv4
   datagrams for P and ours never sees them (a client whose server's replies all went elsewhere, a server deaf to IPv4). So the
   IPv4 side is asked first: an explicit port an IPv4 socket holds is refused (EADDRINUSE); port 0 takes a port free there, then
   binds :: to it (an explicit bind also checks 127.0.0.1:P), and a port taken in between fails with EADDRINUSE: another one.
   0 when bound; -1 with errno when an explicit port is taken; -2 to bind port 0 the plain way (no IPv4 port to be had). */
static int bind_dual(int fd, struct sockaddr_storage *ss, socklen_t sl) {
    uint16_t want = ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
    if (want) {
        if (!ipv4_port_probe(want) && errno == EADDRINUSE)
            return -1;
        return bind(fd, (struct sockaddr *)ss, sl) == 0 ? 0 : -1;
    }
    for (int i = 0; i < 32; i++) {
        uint16_t p = ipv4_port_probe(0);
        if (!p)
            break;
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(p);
        if (bind(fd, (struct sockaddr *)ss, sl) == 0)
            return 0;
        if (errno != EADDRINUSE)
            break;
    }
    ((struct sockaddr_in6 *)ss)->sin6_port = 0;
    return -2;
}
#endif
static int is_wildcard(const uint8_t *a) {
    for (int i = 3; i < (a[0] == 4 ? 7 : 19); i++)
        if (a[i])
            return 0;
    return 1;
}
/* setsockopt for Don't Fragment failed with errno e: a refusal that says nothing about the system's DF support (ENOBUFS, ENOMEM: no
   memory for the option's state, which Darwin's IPV6_DONTFRAG allocates) is transient, as ksl_udp_win.c's df_opt counts WSAENOBUFS,
   so the open fails as that error instead of reporting a socket without DF, which callers take as lasting. Every other refusal
   is lasting: an option or level the system does not have (ENOPROTOOPT; Darwin's IP_DONTFRAG on AF_INET6, EINVAL; a value it
   does not know, EINVAL), or one a policy forbids (a seccomp filter's errno, an LSM's EACCES, gVisor) */
static void df_refused(int e, int *transient) {
    if (e == ENOBUFS || e == ENOMEM)
        *transient = e;
}
#define DF_STEP "Don't Fragment setsockopt"
/* bind_socket with need_df: the socket got no DF for good and was closed unbound */
#define NO_DF_STEP "no Don't Fragment"
#if !defined(__APPLE__)
#ifdef KSL_TEST
static int
    refuse_probe; /* tests: the system refuses probe mode (a seccomp filter, gVisor), as ksl_udp_refuse_probe_for_test sets */
void ksl_udp_refuse_probe_for_test(int on) {
    refuse_probe = on;
}
#else
#define refuse_probe 0
#endif
/* DF on one half of fd ([family] 4: IP_MTU_DISCOVER, on AF_INET6 the v4-mapped half; 6: IPV6_MTU_DISCOVER): probe mode where the
   system takes it (1), else DO mode (2), else 0 (*transient set where the refusal of DO is transient, df_refused). The kernel
   (do_ip_setsockopt, reached for SOL_IP from an AF_INET6 UDP socket through ipv6_setsockopt) refuses IP_MTU_DISCOVER only for a
   value it does not know (EINVAL: PROBE before Linux 2.6.22) and allocates nothing for it: a refusal of both modes comes from a
   policy (seccomp, an LSM) or from a kernel that is not Linux's (gVisor), and lasts */
static int set_df_mode(int fd, int family, int *transient) {
    int probe = family == 6 ? IPV6_PMTUDISC_PROBE : IP_PMTUDISC_PROBE,
        d = family == 6 ? IPV6_PMTUDISC_DO : IP_PMTUDISC_DO;
    int level = family == 6 ? IPPROTO_IPV6 : IPPROTO_IP, opt = family == 6 ? IPV6_MTU_DISCOVER : IP_MTU_DISCOVER;
    if (!refuse_probe && setsockopt(fd, level, opt, &probe, sizeof probe) == 0)
        return 1;
    if (setsockopt(fd, level, opt, &d, sizeof d) == 0)
        return 2;
    df_refused(errno, transient);
    return 0;
}
#else
#include <sys/utsname.h>
/* Whether a Darwin kernel release (uname's "24.1.0") applies IPV6_DONTFRAG to the v4-mapped traffic of a dual-stack socket: from
   Darwin 24 (macOS 15, iOS 18) on. Before, the option takes on such a socket but v4-mapped datagrams leave without DF and are
   fragmented (quic-go sys_conn_df_darwin.go, which therefore sets no DF on a dual-stack socket before macOS 15). Only where the
   loopback check below cannot tell */
static int release_maps_df(const char *release) {
    int major = 0;
    for (const char *c = release; *c >= '0' && *c <= '9' && major < 1000; c++)
        major = major * 10 + (*c - '0');
    return major >= 24;
}
/* Whether this Darwin applies IPV6_DONTFRAG to v4-mapped traffic, tried on the loopback: on two dual-stack sockets with room for
   the datagram (SO_SNDBUF above net.inet.udp.maxdgram, 9216, which refuses a larger send as EMSGSIZE whatever DF says), 20000
   bytes (above lo0's 16384-byte MTU) to ::ffff:127.0.0.1 must go out fragmented without the option and be refused with EMSGSIZE
   with it, while 100 bytes still go: 1 yes, 0 no (fragmented, or v4-mapped sends refused), -1 when the loopback cannot tell
   (the control refused too, no socket). The datagrams go to an AF_INET socket of its own on 127.0.0.1, closed unread */
static int mapped_df_check(void) {
    int r = socket(AF_INET, SOCK_DGRAM, 0), c = socket(AF_INET6, SOCK_DGRAM, 0), d = socket(AF_INET6, SOCK_DGRAM, 0);
    int verdict = -1, off = 0, one = 1, buf = 65536;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_len = sizeof a;
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    static const uint8_t big[20000];
    if (r >= 0 && c >= 0 && d >= 0 && bind(r, (struct sockaddr *)&a, sizeof a) == 0 &&
        getsockname(r, (struct sockaddr *)&a, &al) == 0 &&
        setsockopt(c, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off) == 0 &&
        setsockopt(d, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off) == 0 &&
        setsockopt(c, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf) == 0 &&
        setsockopt(d, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf) == 0 &&
        setsockopt(d, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one) == 0) {
        struct sockaddr_in6 m;
        memset(&m, 0, sizeof m);
        m.sin6_len = sizeof m;
        m.sin6_family = AF_INET6;
        m.sin6_port = a.sin_port;
        m.sin6_addr.s6_addr[10] = m.sin6_addr.s6_addr[11] = 0xff;
        memcpy(&m.sin6_addr.s6_addr[12], &a.sin_addr, 4);
        if (sendto(c, big, sizeof big, 0, (struct sockaddr *)&m, sizeof m) == (ssize_t)sizeof big) {
            ssize_t small = sendto(d, big, 100, 0, (struct sockaddr *)&m, sizeof m);
            int small_errno = errno;
            ssize_t large = sendto(d, big, sizeof big, 0, (struct sockaddr *)&m, sizeof m);
            if (small != 100)
                verdict = small_errno == ENOBUFS || small_errno == EAGAIN ? -1 : 0; /* DF breaks v4-mapped sends */
            else if (large == (ssize_t)sizeof big)
                verdict = 0; /* fragmented: no DF on the v4-mapped half */
            else
                verdict = errno == EMSGSIZE ? 1 : -1;
        }
    }
    if (r >= 0)
        close(r);
    if (c >= 0)
        close(c);
    if (d >= 0)
        close(d);
    return verdict;
}
static int mapped_df; /* 0 not known yet, 1 yes, 2 no: learned once per process (a race only checks twice) */
static int mapped_df_honoured(void) {
    int v = __atomic_load_n(&mapped_df, __ATOMIC_ACQUIRE);
    if (v == 0) {
        int c = mapped_df_check();
        struct utsname un;
        if (c < 0)
            c = uname(&un) == 0 && release_maps_df(un.release);
        v = c ? 1 : 2;
        __atomic_store_n(&mapped_df, v, __ATOMIC_RELEASE);
    }
    return v == 1;
}
#endif
/* DF on the halves fd carries (u->family, u->dual: the IPv4 half on AF_INET or a dual-stack socket, the IPv6 half on AF_INET6), set
   before bind as ksl_udp_win.c does; probe mode where the system takes it: the kernel's path MTU cache must not drive sizes (an
   attacker's ICMP would shrink it: quic-go CVE-2024-53259); DO mode on a half that refuses it (a seccomp filter, gVisor): DF all
   the same, reported as KSL_UDP_DF_DO. KSL_UDP_DF is granted only when every half the socket carries has DF. 0 on a transient
   refusal (*transient, df_refused): not a verdict on DF, the open fails as that error */
static int set_df(ksl_udp *u, int fd, int *transient) {
    int one = 1, v4 = u->family == AF_INET || u->dual, v6 = u->family == AF_INET6, ok4 = 1, ok6 = 1, in_do = 0;
    u->granted &= ~(uint32_t)(KSL_UDP_DF | KSL_UDP_DF_DO); /* nothing left from an attempt that failed */
    u->recverr = 0;
#ifdef __APPLE__ /* Darwin has only the DF bit, as in quic-go sys_conn_df_darwin.go: IP_DONTFRAG on AF_INET (macOS 11 and later;
                    ENOPROTOOPT before), IPV6_DONTFRAG on AF_INET6, which covers the v4-mapped half only from Darwin 24 on
                    (mapped_df_honoured; IP_DONTFRAG is EINVAL there). It does cache a path MTU from an ICMPv6 Packet Too Big
                    (clamped to >= 1280): a larger datagram then fails with EMSGSIZE, a lost slot, and QUIC's 1248-byte IPv6 floor
                    (1200 + headers) still fits, so a forged PTB cannot stop sending */
    if (v6) {
        ok6 = setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one) == 0;
        if (!ok6)
            df_refused(errno, transient);
        ok4 = !v4 || (ok6 && mapped_df_honoured());
    } else if (!(ok4 = setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &one, sizeof one) == 0))
        df_refused(errno, transient);
    in_do = 1; /* the DF bit alone works as DO mode */
#else
    if (v4) { /* on AF_INET6: the v4-mapped half */
        int m = set_df_mode(fd, 4, transient);
        ok4 = m > 0;
        in_do |= m == 2;
    }
    if (v6) {
        int m = set_df_mode(fd, 6, transient);
        ok6 = m > 0;
        in_do |= m == 2;
        if (ok6)
            setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one);
    }
#endif
#ifdef KSL_TEST
    if (v4 && ((u->family == AF_INET6 && no_df_v4_mapped_for_test) || (u->family == AF_INET && no_df_inet_for_test)))
        ok4 = 0;
    if (v6 && no_df_v6_for_test)
        ok6 = 0;
    if (u->family == AF_INET && transient_df_inet_for_test) {
        ok4 = 0;
        *transient = ENOBUFS;
    }
#endif
    int ok = ok4 && ok6;
    if (!ok && *transient)
        return 0;
#ifndef __APPLE__
    /* ICMP errors into the error queue (ADR-0006): Packet Too Big as a DPLPMTUD hint (RFC 8899 section 4.6), validated by the caller.
       The queue also takes port and host unreachable, which set sk_err: ksl_udp_recv drains it and never fails on such an error */
    if (ok) {
        int rv = 1;
        if (v4)
            rv = rv && setsockopt(fd, IPPROTO_IP, IP_RECVERR, &one, sizeof one) == 0;
        if (v6)
            rv = rv && setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &one, sizeof one) == 0;
        u->recverr = rv;
    }
#endif
    if (ok)
        u->granted |= KSL_UDP_DF | (in_do ? KSL_UDP_DF_DO : 0);
    return 1;
}
/* socket, the options bind needs first (DF among them, with KSL_UDP_DF), bind; -1 with errno and the failed step. dual: AF_INET6
   bound to :: with IPV6_V6ONLY off. need_df: a socket that gets no DF for a lasting reason is closed before its bind, step
   NO_DF_STEP (so its port was never taken); a transient DF refusal fails as DF_STEP with that errno */
static int bind_socket(ksl_udp *u, const uint8_t addr[KSL_UDP_ADDR_LEN], int dual, int flags, int need_df,
                       const char **step) {
    int family = dual || addr[0] == 6 ? AF_INET6 : AF_INET, fd = -1;
    *step = "socket";
#ifdef KSL_TEST
    if ((family == AF_INET6 && no_ipv6_for_test) || (family == AF_INET && no_inet_for_test)) {
        int v = family == AF_INET6 ? no_ipv6_for_test : no_inet_for_test;
        errno = v != 1 ? v : EAFNOSUPPORT;
        return -1;
    }
#endif
#ifdef __linux__
    fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else /* Darwin has no SOCK_CLOEXEC/SOCK_NONBLOCK: set them right after creation */
    fd = socket(family, SOCK_DGRAM, 0);
    if (fd >= 0 && cloexec_nonblock(fd) != 0) {
        int e = errno;
        close(fd);
        fd = -1;
        errno = e;
    }
#endif
    if (fd < 0)
        return -1;
    u->family = family;
    u->dual = dual;
    int one = 1, v6only = !dual, transient = 0;
#ifdef __APPLE__
    int r;
#endif
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one,
               sizeof one); /* Darwin: an error never raises SIGPIPE in the host process */
#endif
#ifdef __linux__ /* Darwin has SO_REUSEPORT but hands unicast UDP to one of the sockets only (no flow hashing): loops would starve, so never granted there */
    if (flags & KSL_UDP_REUSEPORT) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0)
            u->granted |= KSL_UDP_REUSEPORT;
    }
#endif
    uint8_t any[KSL_UDP_ADDR_LEN] = {6};
    any[1] = addr[1];
    any[2] = addr[2];
    struct sockaddr_storage ss;
    socklen_t sl = to_sockaddr(dual ? any : addr, &ss);
    if (family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only) != 0 &&
        (dual || u->v6only_needed)) { /* the IPv6 half of a split must not take IPv4 (open_split) */
        *step = "IPV6_V6ONLY";
    } else if ((flags & KSL_UDP_DF) && !set_df(u, fd, &transient)) {
        *step = DF_STEP;
        errno = transient;
    } else if (need_df && (flags & KSL_UDP_DF) && !(u->granted & KSL_UDP_DF)) {
        *step = NO_DF_STEP;
        errno = EOPNOTSUPP;
    }
#ifdef __APPLE__ /* a port the IPv4 side has free too (bind_dual) */
    else if (dual && (r = bind_dual(fd, &ss, sl)) != -2) {
        if (r == 0)
            return fd;
        *step = "bind";
    }
#endif
    else if (bind(fd, (struct sockaddr *)&ss, sl) == 0) {
        return fd;
    } else
        *step = "bind";
    int e = errno;
    close(fd);
    errno = e;
    return -1;
}
static ksl_udp *open_failed(ksl_udp *u, uint32_t code, const char *what, int e, uint32_t *err, char *msg,
                            size_t msglen) {
    if (err)
        *err = code;
    if (msg && msglen) {
        char t[128];
        ksl_errtext(e, t, sizeof t);
        snprintf(msg, msglen, "%s: %s", what, t);
    }
    if (u->fd >= 0)
        close(u->fd);
    if (u->fd4 >= 0)
        close(u->fd4);
    if (u->wake[0] >= 0)
        close(u->wake[0]);
    if (u->wake[1] >= 0)
        close(u->wake[1]);
    pthread_mutex_destroy(&u->err_mu);
    pthread_mutex_destroy(&u->ptb_mu);
    free(u->scratch);
    free(u->tx);
    free(u);
    return NULL;
}
/* the wildcard of [family] (4: 0.0.0.0, 6: ::) on [port] */
static void wildcard_on(uint8_t a[KSL_UDP_ADDR_LEN], int family, uint16_t port) {
    memset(a, 0, KSL_UDP_ADDR_LEN);
    a[0] = (uint8_t)family;
    a[1] = (uint8_t)(port >> 8);
    a[2] = (uint8_t)port;
}
static uint16_t port_of_fd(int fd) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    uint8_t a[KSL_UDP_ADDR_LEN];
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0)
        return 0;
    from_sockaddr(&ss, a);
    return (uint16_t)((a[1] << 8) | a[2]);
}
/* socket() refused with e for a lasting reason: anything but a resource running out (EMFILE, ENFILE, ENOBUFS, ENOMEM, which may
   pass later: the open fails instead). The family missing (EAFNOSUPPORT, EPROTONOSUPPORT) and a policy denying it (EACCES,
   EPERM from AppArmor, SELinux or a seccomp filter) last: that family is done without, as before 0.3.0 */
static int socket_lasting(int e) {
    return e != EMFILE && e != ENFILE && e != ENOBUFS && e != ENOMEM;
}
/* whether 0.0.0.0:[port] is free for an AF_INET socket without SO_REUSEPORT: a socket with SO_REUSEPORT binding it would join
   the reuse group of another socket of this user on that port and take part of its datagrams, so a port-0 split checks before
   its AF_INET half (which carries SO_REUSEPORT for loops > 1) takes a port the IPv6 half was given. A race with a bind in
   between remains: a socket bound to the port that very moment with SO_REUSEPORT */
static int inet_port_free(uint16_t port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return 1; /* no socket to check with: the bind itself decides */
    uint8_t a[KSL_UDP_ADDR_LEN];
    wildcard_on(a, 4, port);
    struct sockaddr_storage ss;
    socklen_t sl = to_sockaddr(a, &ss);
    int ok = bind(s, (struct sockaddr *)&ss, sl) == 0 || errno != EADDRINUSE;
    close(s);
    return ok;
}
/* KSL_UDP_SPLIT: an IPV6_V6ONLY socket on :: (u->fd), then an AF_INET one on 0.0.0.0 (u->fd4) on the port the first got, each with
   DF where need_df (bind_socket). Port 0: a port an IPv4 socket holds (Darwin hands such ports to an IPv6 socket) is given up and
   another taken, up to 16 times. 0 when the IPv6 socket opened: u->fd4 is -1 when the AF_INET one got no DF for a lasting reason
   or does not open (need_df only); -1 with errno and *step otherwise (none left open). Afterwards u->granted holds what both took
   of DF (DF when both have it, DF_DO when either is in DO mode) and REUSEPORT; family AF_INET6, not dual */
static int open_split(ksl_udp *u, const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, int need_df, const char **step) {
    uint16_t want = (uint16_t)((addr[1] << 8) | addr[2]);
    for (int tries = 0; tries < 16; tries++) {
        uint8_t a6[KSL_UDP_ADDR_LEN], a4[KSL_UDP_ADDR_LEN];
        uint16_t first = want;
#ifdef KSL_TEST
        if (!want && split_port_for_test) {
            first = (uint16_t)split_port_for_test; /* once: as if the kernel had given that port to the IPv6 half */
            split_port_for_test = 0;
        }
#endif
        wildcard_on(a6, 6, first);
        u->granted = 0;
        u->v6only_needed = 1;
        int fd6 = bind_socket(u, a6, 0, flags, need_df, step);
        u->v6only_needed = 0;
        if (fd6 < 0)
            return -1;
        uint32_t g6 = u->granted;
        int r6 = u->recverr;
        uint16_t port = port_of_fd(fd6);
        wildcard_on(a4, 4, port);
        int fd4 = -1, e;
        u->granted = 0;
        if (!want && (g6 & KSL_UDP_REUSEPORT) && !inet_port_free(port)) {
            *step = "bind"; /* held for IPv4, maybe in a reuse group our socket would join */
            e = EADDRINUSE;
        } else {
            fd4 = bind_socket(u, a4, 0, flags, need_df, step);
            e = errno;
        }
        uint32_t g4 = u->granted;
        int r4 = u->recverr;
        u->family = AF_INET6;
        u->dual = 0;
        if (fd4 < 0 && strcmp(*step, "bind") == 0 && e == EADDRINUSE && !want) {
            close(fd6); /* that port is held for IPv4: another one */
#ifdef KSL_TEST
            __atomic_add_fetch(&split_retries_for_test, 1, __ATOMIC_RELAXED);
#endif
            continue;
        }
        /* the AF_INET half cannot be had for a lasting reason (no DF for good; no IPv4 here): the IPv6 one alone, where DF is what
           was asked for. A transient refusal, a resource running out, a port held for IPv4, or two sockets asked for that cannot be
           had fail the open */
        if (fd4 < 0 &&
            (!need_df || (strcmp(*step, NO_DF_STEP) != 0 && !(strcmp(*step, "socket") == 0 && socket_lasting(e))))) {
            close(fd6);
            errno = e;
            return -1;
        }
        u->fd = fd6;
        u->fd4 = fd4;
        uint32_t df = fd4 < 0 ? g6 : g6 & g4;
        u->granted = ((g6 | (fd4 < 0 ? 0 : g4)) & KSL_UDP_DF_DO) | (df & (KSL_UDP_DF | KSL_UDP_REUSEPORT));
        if (!(u->granted & KSL_UDP_DF))
            u->granted &= ~(uint32_t)KSL_UDP_DF_DO;
        u->recverr = r6 && (fd4 < 0 || r4);
        return 0;
    }
    *step = "bind";
    errno = EADDRINUSE;
    return -1;
}
/* the options of one descriptor of the socket (v4 / v6: the halves it carries, wildcard: a wildcard was asked): the flags it took of
   ECN, PKTINFO, GSO and GRO; on a split socket ksl_udp_open grants what both took */
static uint32_t sock_options(ksl_udp *u, int fd, int v4, int v6, int flags, int wildcard) {
    int one = 1;
    uint32_t g = 0;
    /* RFC 9000 section 9.7: "Endpoints that send data using IPv6 SHOULD apply an IPv6 flow label in compliance with [RFC6437]". Neither
       system lets an unconnected socket choose the label of one datagram without more state (Darwin not at all; Linux only through
       IPV6_FLOWINFO_SEND, which kernels before 5.6 refuse without a lease per label), but both label on their own once asked: Linux
       with a keyed hash of each datagram's addresses and ports (a new path, a new label), Darwin with one random label per socket.
       A host may leave that off by default (Linux net.ipv6.auto_flowlabels = 2, since 4.3; Darwin net.inet6.ip6.auto_flowlabel = 0):
       ask for it. Best effort: a kernel before 3.17 has neither the option nor automatic labels */
    if (v6)
        u->autoflowlabel = setsockopt(fd, IPPROTO_IPV6, IPV6_AUTOFLOWLABEL, &one, sizeof one) == 0;
    /* 7 MB; Darwin refuses more than kern.ipc.maxsockbuf (8 MB less overhead by default), so halve until the kernel takes it */
    for (int rcv = 7 * 1024 * 1024; rcv >= 256 * 1024 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv) != 0;
         rcv /= 2) {
    }
    for (int snd = 7 * 1024 * 1024; snd >= 256 * 1024 && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd) != 0;
         snd /= 2) {
    }
    if (flags & KSL_UDP_ECN) { /* read marks on the way in; marks on the way out travel as a per-message cmsg */
        int ok = 1;
        if (v6)
            ok = ok && setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &one, sizeof one) == 0;
#ifdef __APPLE__ /* Darwin refuses IP_RECVTOS on an AF_INET6 socket (EINVAL) and reports v4-mapped marks through IPV6_TCLASS */
        if (!v6)
#endif
            if (v4)
                ok = ok && setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &one, sizeof one) ==
                               0; /* Linux: on AF_INET6 it covers v4-mapped traffic */
        if (ok)
            g |= KSL_UDP_ECN;
    }
    /* the destination of each datagram, so a reply leaves from the address it arrived on (RFC 9000 section 9): only a wildcard bind
       needs it, as quic-go sys_conn_oob.go (newConn: IsUnspecified). AF_INET: IP_PKTINFO (IP_RECVPKTINFO, the same option, on Darwin: quic-go
       sys_conn_helper_darwin.go). AF_INET6, dual-stack too: IPV6_RECVPKTINFO, which reports v4-mapped traffic as a v4-mapped
       IPV6_PKTINFO, as msquic datapath_epoll.c (CxPlatSocketContextInitialize); Linux also takes IP_PKTINFO on the dual-stack socket
       for its ipi_spec_dst, which tells a subnet-directed broadcast destination from an address of this host */
    if ((flags & KSL_UDP_PKTINFO) && wildcard) {
        int ok = v6 ? setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof one) == 0
                    : setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one) ==
                          0; /* Darwin: IP_RECVPKTINFO is IP_PKTINFO */
#ifdef __linux__
        if (v4)
            u->v4_spec = ok && (!v6 || setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one) == 0);
#endif
        if (ok)
            g |= KSL_UDP_PKTINFO;
    }
#ifdef __linux__ /* Darwin has no UDP_SEGMENT/UDP_GRO: the caps never grant them and every datagram is its own sendmsg/recvmsg */
    if (flags & KSL_UDP_GSO) {
        int zero = 0;
        if (setsockopt(fd, SOL_UDP, UDP_SEGMENT, &zero, sizeof zero) == 0)
            g |= KSL_UDP_GSO;
    }
    if ((flags & KSL_UDP_GRO) && setsockopt(fd, SOL_UDP, UDP_GRO, &one, sizeof one) == 0)
        g |= KSL_UDP_GRO;
#endif
    return g;
}

ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen) {
    if (!addr || (addr[0] != 4 && addr[0] != 6)) {
        if (err)
            *err = KSL_E_BAD_ARG;
        if (msg && msglen)
            snprintf(msg, msglen, "ksl_udp: bad address");
        return NULL;
    }
    ksl_udp *u = calloc(1, sizeof *u);
    if (!u) {
        if (err)
            *err = KSL_E_NO_MEMORY;
        return NULL;
    }
    if (pthread_mutex_init(&u->err_mu, NULL) != 0) {
        free(u);
        if (err)
            *err = KSL_E_NO_MEMORY;
        return NULL;
    }
    if (pthread_mutex_init(&u->ptb_mu, NULL) != 0) {
        pthread_mutex_destroy(&u->err_mu);
        free(u);
        if (err)
            *err = KSL_E_NO_MEMORY;
        return NULL;
    }
    u->requested = (uint32_t)flags;
    u->wake[0] = u->wake[1] = -1;
    u->fd = u->fd4 = -1;
    /* a wildcard (0.0.0.0 or ::) takes both families on one dual-stack socket, as NIO's DatagramChannel: a client bound to 0.0.0.0
       reaches IPv6 servers and a server on 0.0.0.0 answers IPv6 clients. Without IPv6 (or with :: taken) the requested family alone.
       A wildcard asked with KSL_UDP_DF whose dual-stack socket gets no DF for a lasting reason (RFC 9000 section 14: "In IPv4, the
       Don't Fragment (DF) bit MUST be set if possible") is two sockets on one port instead (KSL_UDP_SPLIT, open_split): IPV6_V6ONLY on
       :: and AF_INET on 0.0.0.0, each with DF, so neither family is lost. Where the AF_INET one gets no DF for good, the IPv6 one
       alone (KSL_UDP_V6_ONLY: IPv4 is the family without DF); where the IPv6 one gets none, AF_INET alone with DF (KSL_UDP_V4_ONLY,
       as NioDatagramIo's AF_INET channel); where neither, the dual-stack socket again, reported without DF, so the caller does not
       use it. DF is set before bind, so a socket that lacks it never held the port. A transient refusal (df_refused) fails the open
       as that error, with no fallback (it is no missing IPv6). KSL_UDP_SPLIT asked goes to the two sockets without trying the
       dual-stack one, as if it had no DF */
    const char *step = "socket";
    int wildcard = is_wildcard(addr), need_df = (flags & KSL_UDP_DF) != 0;
    if (wildcard && !(flags & KSL_UDP_SPLIT))
        u->fd = bind_socket(u, addr, 1, flags, need_df, &step);
    else if (wildcard)
        step = NO_DF_STEP;
    if (u->fd < 0 && strcmp(step, NO_DF_STEP) == 0) {
        if (open_split(u, addr, flags, need_df, &step) == 0) {
            if (u->fd4 >= 0)
                u->granted |= KSL_UDP_SPLIT;
            else
                u->granted |= KSL_UDP_V6_ONLY;
        } else if (need_df &&
                   (strcmp(step, NO_DF_STEP) == 0 || (strcmp(step, "socket") == 0 && socket_lasting(errno)))) {
            uint8_t a4[KSL_UDP_ADDR_LEN];
            wildcard_on(a4, 4, (uint16_t)((addr[1] << 8) | addr[2]));
            u->granted = 0;
            u->fd = bind_socket(u, a4, 0, flags, 1, &step);
            if (u->fd >= 0)
                u->granted |= KSL_UDP_V4_ONLY;
            else if (strcmp(step, NO_DF_STEP) == 0 || (strcmp(step, "socket") == 0 && socket_lasting(errno))) {
                /* no DF anywhere for good: the dual-stack socket again, reported without DF; a transient refusal, a resource
                   running out or a port held for IPv4 fail the open instead */
                u->granted = 0;
                u->fd = bind_socket(u, addr, 1, flags, 0, &step);
            }
        }
    } else if (u->fd < 0 && strcmp(step, DF_STEP) != 0 &&
               (!wildcard || strcmp(step, "socket") != 0 || socket_lasting(errno))) {
        /* the requested family alone: a specific address, or no dual-stack socket to be had (no IPv6 here, :: taken); a dual-stack
           socket() refused for want of a resource (EMFILE, ENFILE, ENOBUFS, ENOMEM) fails the open instead of losing IPv6 */
        u->granted = 0;
        u->fd = bind_socket(u, addr, 0, flags, 0, &step);
    }
    if (u->fd < 0)
        return open_failed(u,
                           step[0] == 's'              ? (socket_lasting(errno) ? KSL_E_NOT_SUPPORTED : KSL_E_NO_MEMORY)
                           : strcmp(step, "bind") == 0 ? KSL_E_BIND
                           : strcmp(step, DF_STEP) == 0
                               ? (errno == ENOBUFS || errno == ENOMEM ? KSL_E_NO_MEMORY : KSL_E_NOT_SUPPORTED)
                               : KSL_E_BAD_ARG,
                           step, errno, err, msg, msglen);
    uint32_t opts = sock_options(u, u->fd, u->family == AF_INET || u->dual, u->family == AF_INET6, flags, wildcard);
    if (u->fd4 >= 0) /* a split socket has what both descriptors took */
        opts &= sock_options(u, u->fd4, 1, 0, flags, wildcard);
    u->granted |= opts;
    u->tos_cmsg_on = (opts & KSL_UDP_ECN) != 0;
    u->pktinfo = (opts & KSL_UDP_PKTINFO) != 0;
    if (opts & KSL_UDP_GSO) {
        u->gso_on = 1;
        u->gso_max = GSO_SEGMENTS;
    }
    u->batch = 16;
#ifdef __linux__
    if (pipe2(u->wake, O_CLOEXEC | O_NONBLOCK) != 0) {
        u->wake[0] = u->wake[1] = -1;
    }
#else /* Darwin: shutdown(2) does not wake a poll on a UDP socket, the pipe is the only way to end a blocked receive: no pipe, no socket */
    if (pipe(u->wake) != 0 || cloexec_nonblock(u->wake[0]) != 0 || cloexec_nonblock(u->wake[1]) != 0)
        return open_failed(u, socket_lasting(errno) ? KSL_E_NOT_SUPPORTED : KSL_E_NO_MEMORY, "wake pipe", errno, err,
                           msg,
                           msglen); /* out of descriptors: KSL_E_NO_MEMORY, as for a socket() that ran out of them */
#endif
    u->scratch = malloc(GRO_MAX);
    u->tx = malloc(GRO_MAX);
    if (!u->scratch || !u->tx)
        return open_failed(u, KSL_E_NO_MEMORY, "malloc", ENOMEM, err, msg, msglen);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getsockname(u->fd, (struct sockaddr *)&ss, &sl) == 0)
        from_sockaddr(&ss, u->local);
    if (wildcard)
        wildcard_on(u->local, addr[0], (uint16_t)((u->local[1] << 8) | u->local[2]));
    /* a wildcard asked: that wildcard reported (0.0.0.0 or ::, whatever the sockets are), with the port the kernel chose */
    u->refs = 1;
    ksl_live_add(KSL_LIVE_UDP, 1);
    ksl_live_add(KSL_LIVE_WAKE, (u->wake[0] >= 0) + (u->wake[1] >= 0));
    return u;
}

ksl_udp *ksl_udp_sender(ksl_udp *base, uint32_t *err, char *msg, size_t msglen) {
    ksl_udp *root = base && base->base ? base->base : base;
    if (!root || ksl_udp_down(base)) {
        if (err)
            *err = KSL_E_BAD_ARG;
        if (msg && msglen)
            snprintf(msg, msglen, "ksl_udp_sender: %s", root ? "the socket is shut down" : "no socket");
        return NULL;
    }
    ksl_udp *c = calloc(1, sizeof *c);
    if (!c || pthread_mutex_init(&c->err_mu, NULL) != 0) {
        free(c);
        if (err)
            *err = KSL_E_NO_MEMORY;
        if (msg && msglen)
            snprintf(msg, msglen, "ksl_udp_sender: out of memory");
        return NULL;
    }
    if (pthread_mutex_init(&c->ptb_mu, NULL) != 0 || !(c->tx = malloc(GRO_MAX))) {
        pthread_mutex_destroy(&c->err_mu);
        free(c);
        if (err)
            *err = KSL_E_NO_MEMORY;
        if (msg && msglen)
            snprintf(msg, msglen, "ksl_udp_sender: out of memory");
        return NULL;
    }
    /* the sending state as it stands on the object cloned: a flag the kernel refused there stays off here */
    c->base = root;
    c->fd = root->fd;
    c->fd4 = root->fd4;
    c->family = root->family;
    c->dual = root->dual;
    c->wake[0] = c->wake[1] = -1;
    c->requested = base->requested;
    c->granted = base->granted;
    c->gso_max = base->gso_max;
    c->batch = base->batch;
    c->gso_on = base->gso_on;
    c->tos_cmsg_on = base->tos_cmsg_on;
    c->pktinfo = base->pktinfo;
    c->recverr = base->recverr;
    memcpy(c->local, root->local, KSL_UDP_ADDR_LEN);
    __atomic_add_fetch(&root->refs, 1, __ATOMIC_ACQ_REL);
    ksl_live_add(KSL_LIVE_UDP, 1);
    return c;
}

int ksl_udp_get(ksl_udp *u, int what, uint8_t *out, size_t cap, size_t *len) {
    if (!u || !out || !len)
        return KSL_ERROR;
    switch (what) {
    case KSL_UDP_GET_FD:
        if (cap < 4)
            return KSL_ERROR;
        be32(out, (uint32_t)u->fd);
        *len = 4;
        return KSL_OK;
    case KSL_UDP_GET_FD2:
        if (cap < 4)
            return KSL_ERROR;
        be32(out, (uint32_t)u->fd4);
        *len = 4;
        return KSL_OK;
    case KSL_UDP_GET_CAPS:
        if (cap < 8)
            return KSL_ERROR;
        be32(out, u->granted);
        be16(out + 4, u->gso_on ? u->gso_max : 0);
        be16(out + 6, u->batch);
        *len = 8;
        return KSL_OK;
    case KSL_UDP_GET_LOCAL:
        if (cap < KSL_UDP_ADDR_LEN)
            return KSL_ERROR;
        memcpy(out, u->local, KSL_UDP_ADDR_LEN);
        *len = KSL_UDP_ADDR_LEN;
        return KSL_OK;
    case KSL_UDP_GET_STATS:
        if (cap < 12)
            return KSL_ERROR;
        be32(out, KSL_RELAXED(u->sends));
        be32(out + 4, KSL_RELAXED(u->recvs));
        be32(out + 8, KSL_RELAXED(u->gso_fallbacks));
        *len = 12;
        return KSL_OK;
    case KSL_UDP_GET_WAITS:
        if (cap < 4)
            return KSL_ERROR;
        be32(out, KSL_RELAXED(u->waits));
        *len = 4;
        return KSL_OK;
    case KSL_UDP_GET_ERROR: {
        if (cap < 4)
            return KSL_ERROR;
        char msg[KSL_MSG];
        err_lock(u);
        uint32_t e = u->last_errno;
        memcpy(msg, u->last_msg, KSL_MSG);
        err_unlock(u);
        msg[KSL_MSG - 1] = 0;
        be32(out, e);
        size_t m = strlen(msg);
        if (m > cap - 4)
            m = cap - 4;
        memcpy(out + 4, msg, m);
        *len = 4 + m;
        return KSL_OK;
    }
    default:
        return KSL_ERROR;
    }
}

void ksl_udp_shutdown(ksl_udp *u) {
    if (!u || __atomic_exchange_n(&u->closed, 1, __ATOMIC_SEQ_CST))
        return; /* one shutdown wins; a blocked receiver reads it with KSL_ALOAD (sequentially consistent: ksl_udp_recv_dst) */
    if (u->base)
        return; /* a sender clone: the socket and its other clones go on */
    if (u->wake[1] >= 0) {
        uint8_t b = 1;
        ssize_t w = write(u->wake[1], &b, 1);
        (void)w;
    }
    if (u->fd >= 0) {
        shutdown(u->fd, SHUT_RDWR);
    }
    if (u->fd4 >= 0)
        shutdown(u->fd4, SHUT_RDWR);
}
/* drops one reference to the socket ksl_udp_open made; the last one closes the descriptor and the wake pair and frees it */
static void udp_release(ksl_udp *u) {
    if (__atomic_sub_fetch(&u->refs, 1, __ATOMIC_ACQ_REL) > 0)
        return;
    ksl_live_add(KSL_LIVE_WAKE, -((u->wake[0] >= 0) + (u->wake[1] >= 0)));
    if (u->fd >= 0)
        close(u->fd);
    if (u->fd4 >= 0)
        close(u->fd4);
    if (u->wake[0] >= 0)
        close(u->wake[0]);
    if (u->wake[1] >= 0)
        close(u->wake[1]);
    pthread_mutex_destroy(&u->err_mu);
    pthread_mutex_destroy(&u->ptb_mu);
    free(u->scratch);
    free(u->tx);
    memset(u, 0, sizeof *u);
    free(u);
}
void ksl_udp_close(ksl_udp *u) {
    if (!u)
        return;
    ksl_udp_shutdown(u);
    ksl_live_add(KSL_LIVE_UDP, -1);
    if (u->base) { /* a sender clone: its own scratch, then its reference to the socket */
        ksl_udp *root = u->base;
        pthread_mutex_destroy(&u->err_mu);
        pthread_mutex_destroy(&u->ptb_mu);
        free(u->tx);
        memset(u, 0, sizeof *u);
        free(u);
        udp_release(root);
        return;
    }
    /* a receiver still inside was woken by the shutdown and leaves the object: waited for however long that takes (a bound here
       freed the socket under a receiver that had not left yet) */
    while (__atomic_load_n(&u->in_recv, __ATOMIC_SEQ_CST) > 0) {
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    udp_release(u);
}

int ksl_udp_take_ptb(ksl_udp *u, uint8_t *quote, uint32_t cap, uint32_t *quote_len, uint8_t dst[KSL_UDP_ADDR_LEN],
                     uint32_t *mtu) {
    if (!u || !quote_len || !dst || !mtu || (cap && !quote))
        return 0;
    pthread_mutex_lock(&u->ptb_mu);
    if (!u->ptb_count) {
        pthread_mutex_unlock(&u->ptb_mu);
        return 0;
    }
    const struct ksl_ptb *p = &u->ptb[u->ptb_head];
    uint32_t n = p->quote_len < cap ? p->quote_len : cap;
    memcpy(quote, p->quote, n);
    *quote_len = n;
    memcpy(dst, p->dst, KSL_UDP_ADDR_LEN);
    *mtu = p->mtu;
    u->ptb_head = (u->ptb_head + 1) % PTB_RING;
    u->ptb_count--;
    pthread_mutex_unlock(&u->ptb_mu);
    return 1;
}
uint64_t ksl_udp_emsgsize(ksl_udp *u, uint32_t *last_size) {
    if (!u)
        return 0;
    if (last_size)
        *last_size = __atomic_load_n(&u->emsgsize_last, __ATOMIC_RELAXED);
    return __atomic_load_n(&u->emsgsize, __ATOMIC_RELAXED);
}
int ksl_udp_take_unreachable(ksl_udp *u, uint8_t dst[KSL_UDP_ADDR_LEN], uint8_t *quote, uint32_t cap,
                             uint32_t *quote_len, uint32_t *kind) {
    if (!u || !dst || (!quote && cap) || !quote_len || !kind)
        return 0;
    pthread_mutex_lock(&u->ptb_mu);
    int news = u->unreach_count != 0;
    if (news) {
        uint32_t i = u->unreach_head;
        uint32_t n = u->unreach[i].quote_len < cap ? u->unreach[i].quote_len : cap;
        if (n)
            memcpy(quote, u->unreach[i].quote, n);
        *quote_len = n;
        *kind = u->unreach[i].kind;
        memcpy(dst, u->unreach[i].dst, KSL_UDP_ADDR_LEN);
        u->unreach_head = (i + 1) % UNREACH_RING;
        u->unreach_count--;
    }
    pthread_mutex_unlock(&u->ptb_mu);
    return news;
}
/* the receiver's note of an unreachable (ksl_udp_recv.c): into the ring unless it is full (a flood only costs the newest) */
void ksl_udp_note_unreachable(ksl_udp *u, const uint8_t dst[KSL_UDP_ADDR_LEN], const uint8_t *quote, uint32_t quote_len,
                              uint32_t kind) {
    pthread_mutex_lock(&u->ptb_mu);
    if (u->unreach_count < UNREACH_RING) {
        uint32_t i = (u->unreach_head + u->unreach_count) % UNREACH_RING;
        if (quote_len > KSL_UDP_PTB_QUOTE)
            quote_len = KSL_UDP_PTB_QUOTE;
        if (quote_len)
            memcpy(u->unreach[i].quote, quote, quote_len);
        u->unreach[i].quote_len = quote_len;
        u->unreach[i].kind = kind;
        memcpy(u->unreach[i].dst, dst, KSL_UDP_ADDR_LEN);
        u->unreach_count++;
    }
    pthread_mutex_unlock(&u->ptb_mu);
}
/* the receiver's side of the ring (ksl_udp_recv.c): a full ring keeps the older messages, a flood only costs the newest */
void ksl_udp_push_ptb(ksl_udp *u, const uint8_t *quote, uint32_t len, const uint8_t dst[KSL_UDP_ADDR_LEN],
                      uint32_t mtu) {
    pthread_mutex_lock(&u->ptb_mu);
    if (u->ptb_count == PTB_RING) {
        u->ptb_dropped++;
        pthread_mutex_unlock(&u->ptb_mu);
        return;
    }
    struct ksl_ptb *p = &u->ptb[(u->ptb_head + u->ptb_count) % PTB_RING];
    p->quote_len = len < KSL_UDP_PTB_QUOTE ? len : KSL_UDP_PTB_QUOTE;
    memcpy(p->quote, quote, p->quote_len);
    memcpy(p->dst, dst, KSL_UDP_ADDR_LEN);
    p->mtu = mtu;
    u->ptb_count++;
    pthread_mutex_unlock(&u->ptb_mu);
}

static int fd_family(int fd) {
    struct sockaddr_storage ss;
    socklen_t l = sizeof ss;
    memset(&ss, 0, sizeof ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &l) != 0)
        return -1;
    return ss.ss_family == AF_INET || ss.ss_family == AF_INET6 ? ss.ss_family : -1;
}
int ksl_udp_fd_df_probe(int64_t fd64) {
    int fd = (int)fd64, family = fd64 < 0 || fd64 > INT32_MAX ? -1 : fd_family(fd);
    if (family < 0)
        return KSL_ERROR;
#ifdef __APPLE__ /* Darwin has only the DF bit (set_df), DO-like: on AF_INET6 IPV6_DONTFRAG covers v4-mapped traffic too from Darwin 24 on
                    (mapped_df_honoured; checked on macOS 26: a v4-mapped send above lo0's MTU is refused; IP_DONTFRAG is EINVAL on
                    that socket), so before it the v4-mapped half is reported without DF and NioDatagramIo tries an AF_INET channel */
    int one = 1;
    if (family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one) != 0)
            return KSL_FD_DF_INET6;
        int v4 = mapped_df_honoured();
#ifdef KSL_TEST
        v4 = v4 && !no_df_v4_mapped_for_test;
#endif
        return KSL_FD_DF_INET6 | KSL_FD_DF_V6_DO | (v4 ? KSL_FD_DF_V4_DO : 0);
    }
    return setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &one, sizeof one) == 0 ? KSL_FD_DF_V4_DO : 0;
#else
    int one = 1, granted = 0, transient = 0;
    /* on AF_INET6: the v4-mapped half, which IPV6_MTU_DISCOVER does not cover; DO where probe mode is refused (DF always) */
    int m4 = set_df_mode(fd, 4, &transient);
    granted |= m4 == 1 ? KSL_FD_DF_V4 : m4 == 2 ? KSL_FD_DF_V4_DO : 0;
    if (family == AF_INET6) {
        granted |= KSL_FD_DF_INET6;
        int m6 = set_df_mode(fd, 6, &transient);
        granted |= m6 == 1 ? KSL_FD_DF_V6 : m6 == 2 ? KSL_FD_DF_V6_DO : 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one);
    }
    return granted;
#endif
}
int ksl_udp_fd_v6only(int64_t fd64) {
    int one = 1;
    if (fd64 < 0 || fd64 > INT32_MAX || fd_family((int)fd64) != AF_INET6)
        return KSL_ERROR;
    return setsockopt((int)fd64, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == 0;
}
int ksl_udp_fd_df_mode(int64_t fd64, int family) {
#ifdef __APPLE__
    (void)fd64;
    (void)family;
    return -1;
#else
    int v = -1;
    socklen_t l = sizeof v;
    if (fd64 < 0 || fd64 > INT32_MAX || (family != 4 && family != 6))
        return -1;
    if (getsockopt((int)fd64, family == 6 ? IPPROTO_IPV6 : IPPROTO_IP,
                   family == 6 ? IPV6_MTU_DISCOVER : IP_MTU_DISCOVER, &v, &l) != 0)
        return -1;
    return v;
#endif
}

#ifdef KSL_TEST
void ksl_udp_push_ptb_for_test(ksl_udp *u, const uint8_t *quote, uint32_t len, const uint8_t dst[KSL_UDP_ADDR_LEN],
                               uint32_t mtu) {
    ksl_udp_push_ptb(u, quote, len, dst, mtu);
}
uint32_t ksl_udp_ptb_dropped_for_test(ksl_udp *u) {
    pthread_mutex_lock(&u->ptb_mu);
    uint32_t d = u->ptb_dropped;
    pthread_mutex_unlock(&u->ptb_mu);
    return d;
}
uint32_t ksl_udp_errqueue_reads_for_test(ksl_udp *u) {
    return KSL_RELAXED(u->errqueue_reads);
}
int ksl_udp_recverr_for_test(ksl_udp *u) {
    return u->recverr;
}
uint32_t ksl_udp_syscalls_for_test(ksl_udp *u) {
    return KSL_RELAXED(u->sends);
}
uint32_t ksl_udp_recv_syscalls_for_test(ksl_udp *u) {
    return KSL_RELAXED(u->recvs) + KSL_RELAXED(u->polls);
}
void ksl_udp_fail_next_gso_for_test(ksl_udp *u, int err) {
    u->fail_next_gso = err;
}
void ksl_udp_fail_next_send_for_test(ksl_udp *u, int err) {
    u->fail_next_send = err;
}
void ksl_udp_set_err_for_test(ksl_udp *u, int e, const char *what) {
    set_err(u, e, what);
}
int ksl_udp_autoflowlabel_asked_for_test(ksl_udp *u) {
    return u->autoflowlabel;
}
int ksl_udp_autoflowlabel_for_test(int fd) {
    int v = -1;
    socklen_t l = sizeof v;
    return getsockopt(fd, IPPROTO_IPV6, IPV6_AUTOFLOWLABEL, &v, &l) == 0 ? v : -1;
}
#ifdef __APPLE__
int ksl_udp_mapped_df_check_for_test(void) {
    return mapped_df_check();
}
int ksl_udp_release_maps_df_for_test(const char *release) {
    return release_maps_df(release);
}
int ksl_udp_df_mode_for_test(int fd) {
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &v, &l) != 0 &&
        getsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &v, (l = sizeof v, &l)) != 0)
        return -1;
    return v;
} /* AF_INET6: IPV6_DONTFRAG */
#else
int ksl_udp_df_mode_for_test(int fd) {
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &v, &l) != 0)
        return -1;
    return v;
}
#endif
static void *blocked_recv(void *arg) {
    ksl_udp *u = arg;
    uint8_t buf[64];
    uint8_t *bufs[1] = {buf};
    uint32_t caps[1] = {64}, lens[1], got;
    uint8_t a[KSL_UDP_ADDR_LEN], e[1];
    ksl_udp_recv(u, bufs, caps, lens, a, e, 1, &got, 5000);
    return NULL;
}
int ksl_udp_close_wakes_for_test(ksl_udp *u) {
    pthread_t t;
    if (pthread_create(&t, NULL, blocked_recv, u) != 0)
        return 100000;
    struct timespec ts = {0, 20000000};
    nanosleep(&ts, NULL);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ksl_udp_shutdown(u);
    pthread_join(t, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ksl_udp_close(u);
    return (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
}
#endif

#elif !defined(_WIN32) /* neither Linux, Apple nor Windows (ksl_udp_win.c): the portable DatagramIo does the work */
ksl_udp *ksl_udp_sender(ksl_udp *base, uint32_t *err, char *msg, size_t msglen) {
    (void)base;
    if (err)
        *err = KSL_E_NOT_SUPPORTED;
    if (msg && msglen)
        snprintf(msg, msglen, "ksl_udp: accelerated UDP needs Linux, Apple or Windows");
    return NULL;
}
ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen) {
    (void)addr;
    (void)flags;
    if (err)
        *err = KSL_E_NOT_SUPPORTED;
    if (msg && msglen)
        snprintf(msg, msglen, "ksl_udp: accelerated UDP needs Linux, Apple or Windows");
    return NULL;
}
int ksl_udp_get(ksl_udp *u, int what, uint8_t *out, size_t cap, size_t *len) {
    (void)u;
    (void)what;
    (void)out;
    (void)cap;
    (void)len;
    return KSL_ERROR;
}
void ksl_udp_shutdown(ksl_udp *u) {
    (void)u;
}
void ksl_udp_close(ksl_udp *u) {
    (void)u;
}
int ksl_udp_take_ptb(ksl_udp *u, uint8_t *quote, uint32_t cap, uint32_t *quote_len, uint8_t dst[KSL_UDP_ADDR_LEN],
                     uint32_t *mtu) {
    (void)u;
    (void)quote;
    (void)cap;
    (void)quote_len;
    (void)dst;
    (void)mtu;
    return 0;
}
uint64_t ksl_udp_emsgsize(ksl_udp *u, uint32_t *last_size) {
    (void)u;
    if (last_size)
        *last_size = 0;
    return 0;
}
int ksl_udp_take_unreachable(ksl_udp *u, uint8_t dst[KSL_UDP_ADDR_LEN], uint8_t *quote, uint32_t cap,
                             uint32_t *quote_len, uint32_t *kind) {
    (void)u;
    (void)dst;
    (void)quote;
    (void)cap;
    (void)quote_len;
    (void)kind;
    return 0;
}
int ksl_udp_fd_df_probe(int64_t fd) {
    (void)fd;
    return 0;
}
int ksl_udp_fd_df_mode(int64_t fd, int family) {
    (void)fd;
    (void)family;
    return -1;
}
int ksl_udp_fd_v6only(int64_t fd) {
    (void)fd;
    return KSL_ERROR;
}
#ifdef KSL_TEST
void ksl_udp_push_ptb_for_test(ksl_udp *u, const uint8_t *quote, uint32_t len, const uint8_t dst[KSL_UDP_ADDR_LEN],
                               uint32_t mtu) {
    (void)u;
    (void)quote;
    (void)len;
    (void)dst;
    (void)mtu;
}
uint32_t ksl_udp_ptb_dropped_for_test(ksl_udp *u) {
    (void)u;
    return 0;
}
uint32_t ksl_udp_errqueue_reads_for_test(ksl_udp *u) {
    (void)u;
    return 0;
}
int ksl_udp_recverr_for_test(ksl_udp *u) {
    (void)u;
    return 0;
}
uint32_t ksl_udp_syscalls_for_test(ksl_udp *u) {
    (void)u;
    return 0;
}
uint32_t ksl_udp_recv_syscalls_for_test(ksl_udp *u) {
    (void)u;
    return 0;
}
void ksl_udp_fail_next_gso_for_test(ksl_udp *u, int err) {
    (void)u;
    (void)err;
}
void ksl_udp_fail_next_send_for_test(ksl_udp *u, int err) {
    (void)u;
    (void)err;
}
void ksl_udp_set_err_for_test(ksl_udp *u, int e, const char *what) {
    (void)u;
    (void)e;
    (void)what;
}
int ksl_udp_df_mode_for_test(int fd) {
    (void)fd;
    return -1;
}
int ksl_udp_close_wakes_for_test(ksl_udp *u) {
    (void)u;
    return 0;
}
void ksl_udp_no_ipv6_for_test(int on) {
    (void)on;
}
void ksl_udp_no_df_v4_mapped_for_test(int on) {
    (void)on;
}
void ksl_udp_no_df_inet_for_test(int on) {
    (void)on;
}
void ksl_udp_no_df_v6_for_test(int on) {
    (void)on;
}
void ksl_udp_transient_df_inet_for_test(int on) {
    (void)on;
}
void ksl_udp_no_inet_for_test(int on) {
    (void)on;
}
void ksl_udp_split_port_for_test(int port) {
    (void)port;
}
uint32_t ksl_udp_split_retries_for_test(void) {
    return 0;
}
#endif
#endif
