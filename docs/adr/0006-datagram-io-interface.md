# ADR-0006. UDP behind the `DatagramIo` interface: portable and accelerated implementations

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02). Implemented in stages: the portable side (2026-10-02), the
accelerated socket on Linux and Android (2026-10-08) and on Apple and Windows (0.2.0, 2026-10-13); the history is at the end.

## Context

`ktor-network` and NIO offer no batched I/O, ECN, GSO/GRO or DF control. Without them QUIC on the JVM is bound by one syscall per packet and cannot do PMTUD or ECN.

## Decision

A `DatagramIo` interface with `capabilities`. Two implementations: a portable one in Kotlin (NIO on JVM/Android, `ktor-network` on Native) and an accelerated native one in `ksl` (Linux/Android: `sendmmsg`/`recvmmsg`, GSO/GRO, ECN, DF; Apple: `sendmsg` + ECN; Windows: `WSASendMsg`). If the accelerated one is unavailable, the portable one is used; the transport enables ECN/GSO according to `capabilities`.

As built (0.2.0): Linux/Android batch `sendmsg` with `UDP_SEGMENT` runs and `recvmsg` with `UDP_GRO` (GSO carries the batching, so `sendmmsg` was not needed); Apple `sendmsg`/`recvmsg` per datagram with ECN and DF; Windows `WSASendMsg`/`WSARecvMsg` with USO/URO, ECN and DF where the system grants them. The transport also enables PMTUD according to the DF grant.

Cross-check 2026-10-02: `ktor-network` on Native closes receiving forever on an empty datagram and copies every packet, so the portable implementation on Native is only good for a client; a Native server requires the accelerated path. The main acceleration axis is GSO (`sendmsg` + `UDP_SEGMENT`, as in quinn/quic-go/ngtcp2), `sendmmsg` is secondary; DF is set when the socket is created (`IP_PMTUDISC_PROBE`), ECN on the JVM is send-only ECT(0); Android 12+ offers an intermediate path through `android.system.Os`.

## Consequences

- The transport does not depend on the platform socket; active migration is simply a new `DatagramIo`.
- The native surface grows by a handful of `ksl_udp_*` functions (57 functions in `ksl.h` after the 2026-10-08 work, see the history).
- Every target of the library has the accelerated socket since 0.2.0, so a QUIC server runs on all of them; the portable
  socket remains the fallback and the explicit choice (`IoPreference.Portable`).

## Design (0.2.0, with the 0.2.1 receive path)

### The `ksl_udp` contract

- **Files.** Linux and Apple share `kuicksilver-native/src/c/ksl_udp.c`, `ksl_udp_send.c` and `ksl_udp_recv.c`, compiled
  under `KSL_UDP_ACCEL` (`#if defined(__linux__) || defined(__APPLE__)`, `ksl_udp_internal.h`); Windows has its own
  `ksl_udp_win.c` (the whole file under `_WIN32`). The `KSL_E_NOT_SUPPORTED` stubs are compiled only where neither applies
  (`#elif !defined(_WIN32)`). The Kotlin wrapper is `io.kuicksilver.tls.KslUdpSocket` (common code over `Ksl.udp*`, JNI and
  cinterop).
- **One socket, batches, no copies.** `ksl_udp_send`/`ksl_udp_recv` take up to `KSL_UDP_MAX_BATCH` (64) slots —
  `PacketBuffer`s that C reads and writes in place: not a single copy in Kotlin, not a single allocation in C after `open`
  (addresses, lengths and ECN marks are fixed-size arrays on the stack of the JNI call). Addresses are 20 bytes (family,
  port, address); link-local IPv6 has no scope id there, so `ksl_udp_recv` drops datagrams from `fe80::/10`.
- **Granted capabilities.** The caller asks for `KSL_UDP_GSO`, `KSL_UDP_GRO`, `KSL_UDP_ECN`, `KSL_UDP_DF` and
  `KSL_UDP_REUSEPORT`; what the system actually granted is read from `KSL_UDP_GET_CAPS` (flags | gso max | batch), and a
  fallback inside C (below) withdraws a grant at run time.
- **Shutdown from another thread.** `ksl_udp_shutdown` wakes a blocked `ksl_udp_recv` and closes the socket;
  `ksl_udp_close` frees the object after the receiver has left. `KslUdpSocket` keeps the count of threads inside a native
  call and the shutdown flag in one atomic: entering after shutdown is impossible, `close` frees memory only at a zero
  count, so a use-after-free between the check and the call is ruled out. The getters (`grantedFlags`, `gsoMaxSegments`,
  `batch`, `stats`) enter through the same counter and return the last value read after `shutdown`.
- **One socket, several senders (0.3.0).** One thread sends on a `ksl_udp` object: the joined GSO/USO run lives in its
  `tx` scratch. `ksl_udp_sender(base)` (additive under ABI 7) makes a send-only clone for another thread: the same
  descriptor (`SOCKET` on Windows, where `WSASendMsg` is safe from several threads on one socket), its own `tx`, its own
  error, counters and sending state copied from the object cloned (granted GSO/USO, ECN, DF, PKTINFO; a fallback one clone
  takes after a kernel refusal stays with that clone). A receive on a clone answers `KSL_ERROR` with `KSL_E_NOT_SUPPORTED`:
  the socket's receiver alone reads. The socket counts its owner and its clones (`refs`): `ksl_udp_close` of a clone frees
  only the clone, and the descriptor and the wake pair close with the last close of the group, in any order; after the
  socket's shutdown a clone's send fails with `ESHUTDOWN` (`WSAESHUTDOWN`). Each clone counts in `KSL_LIVE_UDP` and holds
  no wake descriptor. `KslUdpSocket.sender()` wraps it; the in-process loop dispatch of `loops > 1` (below) gives every loop
  its own clone. Tests: `test_udp.c` / `test_udp_win.c` `udp_sender_clones_send_concurrently` (four threads, 10 000
  datagrams each through four clones, all 40 000 received intact by the socket; clean under `KSL_TSAN=1`),
  `udp_sender_outlives_base_close_order`, `negative_udp_sender_cannot_receive`; `KslUdpSenderTest`.
- **`KslDatagramIo`** (`kuicksilver-quic/src/commonMain`) is the `DatagramIo` over `KslUdpSocket`: `PacketBatch` slots go
  to C as they are; `receive` blocks a `Dispatchers.IO` thread in 100 ms slices until the first datagram or close. Since 0.2.1, while
  datagrams keep coming the endpoint loop reads it on its own thread instead (`receiveNow`, `runtime/BatchReceiver.kt`):
  what is queued, or what arrives within 1 ms and before the loop's next timer, and the loop's queued work still runs after
  every 16 datagrams or 1 ms; the hand-off to an I/O thread and back cost more CPU than the QUIC work of a batch of a few
  datagrams (docs/benchmarks.md). Also since 0.2.1, `ksl_udp_recv` calls `recvmsg` first and polls only on an empty queue (not on Windows); peer
  addresses are a 64-entry cache keyed by the 20 bytes (one `InetSocketAddress` instance per peer: the core compares paths
  by reference), destination addresses a cache of the last 4 by identity. `capabilities` (a `StateFlow`) are re-read from
  `KSL_UDP_GET_CAPS` every 256 sends and after a short send, so a fallback in C shows up with that delay; the datagrams
  themselves are not lost during it.
- **Choice and fallback.** `DatagramIo.open(local, prefer = Accelerated)` returns `KslDatagramIo` where
  `KslUdpSocket.supported` (every target since 0.2.0: Linux, Android, Apple and Windows, JVM and Kotlin/Native), otherwise
  the portable one; `IoPreference.Portable` always returns the portable one. `supported` answers false when its loopback
  probe fails for any reason (for example `bind` refused by the App Sandbox), and a single accelerated socket refused at
  bind time falls back to the portable one with one line on standard error; with `loops > 1` the failure surfaces.
- **Endpoint shutdown order.** `EndpointLoop.close()` closes the socket first (waking a receive blocked in a native call),
  waits for the receiver, and only then frees the `PacketBatch`es, whose memory a Native receive writes into. A receive
  error closes the whole endpoint; a send error loses the packet, not the connection.

### Readiness model

`ksl_udp_recv` is a blocking batch call on the caller's thread into slots the caller owns for that call only; it waits
for at most one slice (`KslDatagramIo` uses 100 ms) on two descriptors, the socket and a wake-up channel that
`ksl_udp_shutdown` signals.

- **Linux:** `poll` over the socket and a `pipe2` wake pipe. Without the pipe the receive still ends within its slice.
- **Apple:** the same `poll`, with `pipe` + `fcntl(O_NONBLOCK, FD_CLOEXEC)`. Darwin's `shutdown(2)` does not wake a `poll`
  on a UDP socket, so the pipe is the only way to end a blocked receive: without it `ksl_udp_open` fails.
  **`poll`, not kqueue:** kqueue pays off when one thread multiplexes many sockets (msquic `datapath_kqueue.c` runs its own
  event loop over every socket of the process); here it would add a kqueue descriptor per socket and a second receive
  loop for the same two-descriptor wait, while `poll` keeps one receive path for Linux and Apple.
- **Windows:** `WSAPoll` over the socket and a **wake socket**: a UDP socket on 127.0.0.1, bound with
  `SO_EXCLUSIVEADDRUSE` and connected to itself. `ksl_udp_shutdown` sends it one byte; being connected, it accepts
  datagrams only from itself, so no other local process can fake a shutdown, and a readiness without the closed flag is
  drained and ignored. Without a wake socket the receive waits in 50 ms slices. `POLLERR`/`POLLHUP` without data read and
  clear `SO_ERROR`; with nothing pending the rest of the slice is waited out on the wake socket (no spin).
  **`WSAPoll`, not IOCP:** IOCP (as msquic uses) would need overlapped receives posted ahead into buffers C owns across
  calls and a completion thread — a second ownership model for the slots and an allocation pattern the contract excludes
  ("no allocation after open"). Known `WSAPoll` defects concern TCP `connect` failures only. If profiling on Windows shows
  the readiness path is the bottleneck, RIO/IOCP is the next step.

### Send-error classes

Every send error falls into one of four classes, on every platform (POSIX codes in `ksl_udp_send.c`, Winsock codes in
`ksl_udp_win.c`):

1. **Backpressure** — the queue is full: `EAGAIN`/`EWOULDBLOCK` and `ENOBUFS` (Linux's qdisc or Darwin's interface queue;
   backpressure since the macOS server review, 2026-10-13). `KSL_OK` with a partial `sent`; the caller sends the rest later.
2. **Slot loss** — this datagram is lost on the wire, the socket lives on and loss detection repairs it: destination errors
   (`EINVAL` caused by the destination, `EAFNOSUPPORT`, `EADDRNOTAVAIL`, `EDESTADDRREQ`: port 0, link-local IPv6, a family the
   socket cannot reach) and transient ones (`EMSGSIZE`, `EPERM` after one retry, `EACCES`, `ENETUNREACH`, `EHOSTUNREACH`,
   `ENETDOWN`, `EHOSTDOWN`, `ENOMEM`, `ECONNREFUSED`). `EMSGSIZE` counts as sent: PMTUD learns from the loss. The `EPERM`
   retry budget is restored after a successful send. On Windows the same set with Winsock codes (`WSAEMSGSIZE`,
   `WSAEACCES`, `WSAENETUNREACH`, `WSAEHOSTUNREACH`, `WSAENOBUFS`, `WSAECONNRESET`, `WSAENETRESET`, `WSAECONNREFUSED`,
   `WSAENETDOWN`), without the `EPERM` retry.
3. **Feature fallback** — the kernel refuses a feature, which is switched off for the socket and withdrawn from the
   grant: `EIO`/`ENOTSUP` on a GSO send (the segments then go one by one); `EINVAL` on GSO only if the first segment then
   goes out alone; `EINVAL` on a single send with a mark only if the same datagram without the `IP_TOS` cmsg goes out. A
   repeated single send always decides between the feature and the destination, so a forged Initial from port 0 can
   neither switch ECN or GSO off nor abort a batch. `EINVAL`/`EMSGSIZE` on a run whose segment exceeds 1200 bytes (a
   narrow link) resends the run one by one and keeps GSO. On Windows, `WSAEOPNOTSUPP`/`WSAENOPROTOOPT` on a USO send, or a
   `WSAEINVAL` the single-datagram probe pins on the USO cmsg, switch USO off; any other error resends that run one by one
   and keeps USO for the next run.
4. **Socket error** — anything else is `KSL_ERROR` and fails the endpoint's send, not the process.

Receive errors on Windows: `WSAENETDOWN`/`WSAENOBUFS` are a slice without data (`KSL_WANT_READ`), `WSAECONNRESET` is skipped
and `SIO_UDP_CONNRESET`/`SIO_UDP_NETRESET` are off (an ICMP unreachable must not fail the next receive); `WSAEMSGSIZE`/
`MSG_TRUNC` drop the datagram whole, as an oversized datagram is dropped whole on Linux and Apple.

### Dual-stack binds

NIO's `DatagramChannel.open()` is dual-stack and takes `0.0.0.0` as `::`; the accelerated socket matches it (macOS server
review, 2026-10-13). On Linux and Apple a wildcard (`0.0.0.0` or `::`) opens one `AF_INET6` socket bound to `::` with
`IPV6_V6ONLY = 0`: an IPv4 destination leaves as `::ffff:a.b.c.d`, a v4-mapped source is reported as IPv4 (family 4), and a
`0.0.0.0` request still reports `0.0.0.0` as its local address. A specific address keeps its own family, and IPv6 ones stay
`IPV6_V6ONLY`. When the dual-stack socket cannot be made (no IPv6 in the kernel, `::` taken), `0.0.0.0` falls back to an
`AF_INET` socket. Before this, the Ktor client's endpoint on `0.0.0.0:0` could not reach an IPv6 h3 server (the slot was
lost, the handshake timed out) and a Ktor server on the default host answered HTTP/3 over IPv4 only while its TCP
listener took IPv6.

Darwin binds the dual-stack socket without looking at the IPv4 sockets: port 0 can come back as a port an `AF_INET` socket
holds (`127.0.0.1:P` or `0.0.0.0:P`), and an explicit `::` port succeeds beside `0.0.0.0:P`; that IPv4 socket then receives
every IPv4 datagram for the port and ours none (with 4000 IPv4 ports in use, one wildcard open in five collided, and a client
whose handshake replies went to the other socket timed out). So on Apple `ksl_udp` asks the IPv4 side first: port 0 takes a
port an `AF_INET` socket on `0.0.0.0:0` was given and releases, then binds `::` to it (an explicit bind is refused beside
`127.0.0.1:P`; a port taken in between fails with `EADDRINUSE` and another one is tried), and an explicit port an IPv4 socket
holds is refused (`udp_wildcard_port_free_on_ipv4_side`, `udp_wildcard_port_held_on_ipv4_refused`). Linux (arm64 kernel
in Docker) and Windows 11 check both sides themselves: neither hands a dual-stack socket (Windows: `0.0.0.0` or `::`) a port an
IPv4 socket holds, and both refuse `::` beside `0.0.0.0:P`; the same tests guard Windows
(`udp_win_wildcard_port_free_on_ipv4_side`, `udp_win_wildcard_port_held_on_ipv4_refused`).

ECN and DF cover both halves: the outgoing mark's cmsg follows the destination (`IP_TOS` for IPv4: Linux ignores
`IPV6_TCLASS` for a v4-mapped peer); Linux sets `IP_RECVTOS` and `IP_MTU_DISCOVER = PROBE` on the `AF_INET6` socket for the
v4-mapped half beside `IPV6_RECVTCLASS`/`IPV6_MTU_DISCOVER`; Darwin refuses `IP_RECVTOS` and `IP_DONTFRAG` there (`EINVAL`),
but `IPV6_RECVTCLASS` reports v4-mapped marks and `IPV6_DONTFRAG` sets DF on v4-mapped datagrams from Darwin 24 (macOS 15,
iOS 18) on (a 20000-byte datagram to `127.0.0.1` over `lo0`, MTU 16384, fails with `EMSGSIZE`, while the same socket without
the option sends it fragmented; both sockets need `SO_SNDBUF` above `net.inet.udp.maxdgram`, 9216, which refuses a larger send
as `EMSGSIZE` whatever DF says).

**No DF on the IPv4 half: two sockets on one port (0.3.0).** RFC 9000 section 14: "In IPv4, the Don't Fragment (DF) bit
MUST be set if possible". Owner decision on bind defaults: every interface, IPv6 and IPv4; two sockets where one dual-stack
socket is impossible. DF is set before `bind` on every platform, on the halves the socket carries (the IPv4 one on `AF_INET`
or a dual-stack socket; `::1` carries IPv6 alone). On Linux and Apple a wildcard (`0.0.0.0` or `::`; the Ktor server's
host-less connectors bind `::`) asked with `KSL_UDP_DF` whose dual-stack socket gets no DF for a lasting reason is two
sockets on one port in one `ksl_udp` (`KSL_UDP_SPLIT`, `open_split`): `IPV6_V6ONLY` on `::`, bound first, then `AF_INET`
on `0.0.0.0` on the port it got, each with DF. Port 0 gives up a port an IPv4 socket holds (an `IPV6_V6ONLY` bind does not
look at IPv4 sockets, on Darwin nor Linux) and takes another, up to 16 times; an explicit port an IPv4 socket holds fails
with `KSL_E_BIND`, leaving nothing open. A send goes through the socket of its destination's family, a receive takes from
both (the one it is on until it is empty, then the other; each call starts on the other one than the last ended on, so a
flood on one family delays the other by one call at most), a shutdown wakes a receive blocked on both, and the error queue
of each is drained (`KSL_UDP_GET_FD2` is the `AF_INET` descriptor; Android binds both to its network). It is one socket
above `ksl`: `KslDatagramIo` sees one `DatagramIo`, so a peer stays on the socket of its family, paths, migration (RFC 9000
section 9) and the preferred-address sockets work as on the dual-stack socket, and `KslDatagramIo.open` (and
`NioDatagramIo.open` for its two channels) says so at Info the first time in the process, at Debug after
(`SplitSocketLog`; "UDP on [::]:P uses two sockets (IPv6-only and IPv4) on one port: the IPv4 half of a dual-stack socket
has no Don't Fragment here"). Where the `AF_INET` socket gets no DF for good or does not open, the IPv6-only one alone
(`KSL_UDP_V6_ONLY`: IPv4 is the family without DF); where the IPv6-only one gets none, `AF_INET` alone with DF
(`KSL_UDP_V4_ONLY`: IPv6 is the family without DF, as `NioDatagramIo`'s AF_INET channel); where neither, the dual-stack
socket again, reported without DF and not used. `KslDatagramIo` reports the family without DF as `noDontFragmentFamily`,
reports its slots as refused for want of DF and lets C lose them. A transient refusal (`ENOBUFS`/`ENOMEM`) fails the open
as `KSL_E_NO_MEMORY` and reopens nothing. A socket of a specific address is never split. `KSL_UDP_SPLIT` can also be asked
for (as if the dual-stack socket had no DF; the Kotlin test hook `datagramIoSplitForTest` asks for it). The JVM's portable
socket does the same with two channels (`NioDatagramIo`: `IPV6_V6ONLY` through `ksl_udp_fd_v6only` on the JVM, which the
JDK cannot set, and `android.system.Os` on Android; without either, an IPv4 bind takes its AF_INET channel and `::` keeps
the dual-stack one with IPv4 refused). Windows splits the same way (see the Windows section). A `socket()` refused for want
of a resource (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`; `WSAEMFILE`, `WSAENOBUFS`) is no missing family: the open fails
(`KSL_E_NO_MEMORY`; the Darwin wake pipe out of descriptors too) instead of serving one family, or none, for good. Every
other refusal of `socket()` lasts and that family is done without, as before 0.3.0: the family missing (`EAFNOSUPPORT`), a
policy denying it (`EACCES`/`EPERM` from AppArmor, SELinux or seccomp), a Winsock provider missing or failing
(`WSAEINVALIDPROVIDER`, `WSAEPROVIDERFAILEDINIT`) (`socket_lasting`; `udp_df_fallback_split_socket_resources` checks EMFILE
and EACCES on either family). With `KSL_UDP_REUSEPORT` (loops > 1, Linux) a port-0 split first checks with a throwaway `AF_INET` bind
without `SO_REUSEPORT` that the port its IPv6 half got is free for IPv4 (`inet_port_free`): its `AF_INET` half carries
`SO_REUSEPORT` for the loops' twins, and binding a port another socket of this user holds with `SO_REUSEPORT` would join
that reuse group and take part of its datagrams; binding the half without `SO_REUSEPORT` instead would keep the twins off
it. A socket bound to the port that very moment with `SO_REUSEPORT` still races the check. When each platform refuses DF
on the IPv4 half, and for how long:

- **Linux.** `IP_MTU_DISCOVER` at `SOL_IP` on an `AF_INET6` UDP socket reaches `do_ip_setsockopt` through
  `ipv6_setsockopt` (`level == SOL_IP`), which refuses only a value it does not know (`EINVAL`: `PROBE` before 2.6.22,
  where `DO` is taken instead) and allocates nothing; the v4-mapped send path (`udp_sendmsg`) reads that setting. So a
  stock kernel never refuses it; a refusal of both modes comes from a policy (a seccomp filter's errno, an LSM's `EACCES`)
  or a kernel that is not Linux's (gVisor), and lasts for the process. `ENOBUFS`/`ENOMEM` would be transient; the kernel
  does not return them here. Reasoned from the kernel's documented behaviour and the call path above (no kernel source
  in the reference set).
- **Apple.** `IP_DONTFRAG` exists from macOS 11 (`ENOPROTOOPT` before) and is `EINVAL` on an `AF_INET6` socket, so the
  v4-mapped half has only `IPV6_DONTFRAG`, which takes on a dual-stack socket on every supported release but leaves
  v4-mapped datagrams without DF (fragmented) before Darwin 24: a silent, lasting refusal on macOS 12–14 and iOS 15–17,
  which `ksl` supports (quic-go `sys_conn_df_darwin.go` sets no DF on a dual-stack socket before macOS 15 for this reason;
  no XNU source in the reference set). `ksl_udp.c` learns it once per process on the loopback (`mapped_df_check`: 20000
  bytes to `::ffff:127.0.0.1` sent fragmented by a control socket without DF, refused with `EMSGSIZE` with
  `IPV6_DONTFRAG`, while 100 bytes still go), and only when the loopback cannot tell from the Darwin release (24 or
  later). `ENOBUFS`/`ENOMEM` (`IPV6_DONTFRAG` allocates the socket's IPv6 options) are transient. `ksl_udp_fd_df_probe`
  reports no DF on the v4-mapped half of the JDK's dual-stack socket by the same check, and without `ksl` `NioDatagramIo`
  runs it through the JDK's option (`appleMapsDfCheck`; macOS 15 or later by `os.version` where it cannot tell), so the
  portable socket splits, or takes its AF_INET channel, there too.
- **Windows.** See the Windows section: `IP_DONTFRAGMENT` refused on the v4-mapped half for good, `WSAENOBUFS` and
  `WSAENETDOWN` transient.

The C tests reach every branch through `KSL_TEST` seams on port 0 and on an explicit port (`udp_df_fallback_*` on Linux and
Apple, `udp_win_df_fallback_*` on Windows): DF refused on the v4-mapped half, on the IPv6 half, on `AF_INET` for good or
transiently, `socket(AF_INET)` failing for want of the family or of a descriptor (`EMFILE`), a port-0 first try on a port
IPv4 holds (given up, counted), 2000 IPv4 ports held beside port 0 (the soft `RLIMIT_NOFILE` raised and the count capped
below it), an explicit port held, a reuse group not joined (Linux), the `AF_INET` socket's error queue drained (Linux),
one receive call taking both families, a flood on either socket not delaying the other past two calls, a shutdown waking a
receive on both, and the wake pipe failing after the two sockets opened; no host available refuses DF on its own. Above them `KslDatagramIoTest.aSplitWildcardReachesBothFamiliesWithDf`, `NioDatagramIoTest`
(`.aWildcardWithoutDfOnTheDualStackIpv4HalfIsTwoChannels`, `.aSplitSocketTakesOnePortForBothChannels`,
`.negative_noSplitWhereItCannotBeHad`, `.appleJdkOptionCoversV4MappedTrafficFromMacOs15Only`) and the Ktor server's
`ServerEveryInterfaceTest.http3ServesBothFamiliesOnTwoSocketsWithoutDfOnTheIpv4Half` (HTTP/3 over `127.0.0.1` and `::1`
on one port, JVM and Kotlin/Native).

Windows differs in one point: every IPv6 socket is dual-stack (`IPV6_V6ONLY = 0`, also for a specific IPv6 address), with
v4 peers reported and addressed as family 4 (v4-mapped inside C). A wildcard `0.0.0.0` opens the dual-stack socket on `::`
on the requested port (`udp_win_wildcard_explicit_port_kept`) and reports `0.0.0.0` with that port, as on Linux and Apple, so the Ktor client's `0.0.0.0:0` endpoint reaches IPv6
servers; without IPv6 it falls back to `AF_INET` (before the 0.2.0 Windows fixes, `0.0.0.0` gave an IPv4-only socket
there).

### Local addresses on a wildcard bind (0.3.0)

A path is the 4-tuple (RFC 9000 section 9), and a client drops packets from an address it did not send to. A socket bound to
`0.0.0.0` or `::` asks for `KSL_UDP_PKTINFO` (granted on a wildcard bind only, as quic-go asks for packet info only on an
unspecified address): `ksl_udp_recv_dst` reports each datagram's destination (`IP_PKTINFO` on `AF_INET`, `IPV6_RECVPKTINFO` on
`AF_INET6` and dual-stack sockets, whose IPv4 traffic comes v4-mapped; `IP_PKTINFO` and `IPV6_PKTINFO` on Windows) and
`ksl_udp_send_src` sends a slot from a named source (`IP_PKTINFO` with `ipi_spec_dst` for IPv4, also on a dual-stack socket,
`IPV6_PKTINFO` for IPv6; `IN_PKTINFO` / `IN6_PKTINFO` through `WSASendMsg`). No interface index travels: the 20-byte address
has no room for it, and with index 0 the kernel routes from the named source. Slots with different sources never share a GSO
run. Multicast, broadcast (subnet-directed: Linux `ipi_spec_dst`, Darwin a check against the interface addresses, read at most once a second and limited to the first 16 IPv4 addresses, so a datagram to a later one is answered from the route's choice, Windows `MSG_BCAST`) and IPv6
link-local destinations are reported as unknown. `KslDatagramIo` carries the address as `PacketBatch.localAddress`; the core fixes
it per server path when the path is made (as quinn-proto and quic-go) and names it on every datagram of that path ([RFC 9000 details](../spec/rfc/9000.md#s9-local-address-of-a-server-path)). The portable sockets (NIO,
ktor-network) have no such call: on a multi-address host a server there binds the address clients use. Tests: `test_udp.c`
`udp_pktinfo_*`, `test_udp_win.c` `udp_win_pktinfo_*`, `KslDatagramIoTest.wildcardSocketReportsTheDestinationAndRepliesFromIt`,
`wildcardServerHandshakesOnTheSecondAddress`.

### `SO_REUSEPORT` grant and `loops > 1`

Several endpoint loops on one port (`LoopGroup`) use kernel flow hashing over `SO_REUSEPORT` sockets where the kernel
offers it. `ksl_udp` sets `SO_REUSEPORT` only when asked and reports `KSL_UDP_REUSEPORT` only when the kernel took it.
`LoopGroup` checks that grant on the first socket (through an injectable opener). With it, each loop binds its own socket
on the port. Without it no second socket is bound (it would fail with a socket error, or on Darwin take every datagram):
since 0.3.0 the loops share the first socket in process (below; before, `bind` threw `UnsupportedOperationException`).
The check is the grant, not the platform, so in-process routing covers:

- **Apple:** Darwin accepts the option but hands a port's unicast datagrams to one of the sockets (the last bound), with
  no flow hashing: with four loops, `MultiLoopTest` saw 100 of 100 connections on one loop. `ksl_udp` never sets or
  grants `KSL_UDP_REUSEPORT` there.
- **Windows:** the socket is bound with `SO_EXCLUSIVEADDRUSE` (Windows `SO_REUSEADDR` would let another socket take the
  port over, msquic does the same), so `KSL_UDP_REUSEPORT` is never granted.
- **Linux** with a seccomp filter that refuses `SO_REUSEPORT`.
- A caller-supplied `DatagramIo` (`QuicEndpointConfig.io`), which balances nothing either.

**In-process routing (0.3.0).** One socket, one receiver: `runtime/SocketDispatcher.kt` blocks a `Dispatchers.IO` thread
in the socket's receive (100 ms slices, a shutdown wakes it) and hands each datagram to the loop its connection ID names
(`endpoint/DispatchRoute.kt`, a sans-IO wrapper over `CidRoute.ownerLoop`; a long header naming no loop goes to
`SipHash(group key, DCID) mod loops`, a short one to loop 0). The datagram is copied into that loop's ring of 512 slots,
written by the receiver and read by the loop with no lock and no allocation per datagram; a full ring drops and counts
(`EndpointStats.datagramsDispatchDropped`), the receiver never waits. Each loop sees the socket as a `LoopInbox`, a
`DatagramIo` whose sends go to the loop's own `ksl_udp_sender` clone ("One socket, several senders" above), or to a
caller's socket under one lock; `EndpointLoop` is unchanged but for recognising a non-suspending sender by
`NonSuspendingSend` instead of `KslDatagramIo`. The socket closes with the last loop's inbox, after every loop sent its
CONNECTION_CLOSEs. A receive failure fails every inbox of that socket, so the loops react as to a socket of their own: the
main socket's failure ends the group, a preferred-address socket's takes the preferred address down group-wide. A
Stateless Reset names no ID of ours: the loops record their connections' peer reset tokens in one `ResetTokenIndex`, and
a datagram ending with one goes to its loop (RFC 9000 section 10.3.1). After each receive round the receiver drains the
socket's ICMP Packet Too Big ring (Linux, Android) and offers each message to every loop, which validates the quote
against its own connections. The preferred-address sockets are shared the same way. Plain
Darwin and Windows alternatives were not taken: separate ports with `preferred_address` (the handshake still lands on
one socket, a client may ignore the address, extra ports break on NATs and firewalls) and Windows per-CPU sockets with
`SIO_CPU_AFFINITY` (msquic; depends on RSS, absent on loopback and many VMs; later, and only on a measurement). msquic
on Darwin (one datapath partition whose CID carries the partition index) and quic-go (one reading goroutine) work the
same way. Tests: `DispatchRouteTest`, `DispatchedGroupTest` (four loops on one in-memory socket), `MultiLoopTest` (real
sockets on every OS).

### Linux and Android

- Runs of slots with the same address, mark and length (the last one may be shorter) go out in one `sendmsg` with
  `UDP_SEGMENT`; a run starts only with two equal lengths, so a datagram larger than the following ones (a PMTU probe)
  never sets the `gso_size` of the whole run. A run holds at most 64 segments and as many bytes as one IP datagram carries
  (65507 to an IPv4 peer, 65527 to an IPv6 one; the kernel refuses more with `EMSGSIZE`, 0.2.1). Receiving is `recvmsg` with `UDP_GRO` into a 64 KiB buffer; the segments are
  spread over the slots inside C, the remainder waits for the next call (`PacketBatch`/`handleDatagram` see no offsets).
- ECN: the per-datagram mark is the `IP_TOS`/`IPV6_TCLASS` cmsg (not `setsockopt`, so a batch with different marks costs no
  extra syscalls), received through `IP_RECVTOS`/`IPV6_RECVTCLASS`.
- DF: `IP_PMTUDISC_PROBE` + `IPV6_DONTFRAG`, never `_DO`: the kernel does not substitute the size from its PMTU cache, and a
  forged ICMP PTB does not break sending (quic-go CVE-2024-53259).
- `SO_RCVBUF`/`SO_SNDBUF` 7 MB, `SO_REUSEPORT` by flag.
- ICMP error queue (ksl ABI 7, 0.3.0): with DF the socket also sets `IP_RECVERR`/`IPV6_RECVERR`. The kernel then queues the
  ICMP errors about datagrams we sent and sets `sk_err`, which the next `recvmsg` reports once (`ECONNREFUSED`,
  `EHOSTUNREACH`, `ENETUNREACH`, `EMSGSIZE`, `EHOSTDOWN`) and which keeps `poll` answering `POLLERR` until the queue is read. `ksl_udp_recv` drains
  the queue with `MSG_ERRQUEUE` (16 messages per drain, counted toward its drop bound, so a flood of ICMP still ends the call
  at its deadline) and treats such an error as a dropped datagram, never as a broken socket; a send that meets a pending
  ICMP error goes once more — `EMSGSIZE` too, which a Packet Too Big (forged or not) leaves for the next send of any size: it
  is counted (`ksl_udp_emsgsize`) only when the retry fails the same way, and a GSO run that meets it keeps GSO. The retry
  costs one extra system call per genuine local `EMSGSIZE`, on purpose: it is what tells a forged error from a real one. Only ICMP-origin "fragmentation needed" (type 3 code 4) and ICMPv6 Packet Too Big (type 2) with
  an MTU of 68–65535 are kept: a ring of 16 in the socket (newer ones dropped when it is full) with the first 64 bytes of
  the quoted datagram and its destination, read with `ksl_udp_take_ptb`. They are hints for DPLPMTUD that the QUIC core
  validates (RFC 8899 §4.6, RFC 9000 §14.2.1); ksl never acts on them. Port unreachable, our own `SO_EE_ORIGIN_LOCAL`
  `EMSGSIZE` and the rest are only taken off the queue. `ksl_udp_emsgsize` counts the sends lost to `EMSGSIZE` with the
  latest size, on every platform.

### Apple (macOS, iOS)

- **No GSO/GRO.** Darwin has no `UDP_SEGMENT`/`UDP_GRO`. The run-joining code is not compiled there; a batch leaves as one
  `sendmsg` per datagram and arrives as one `recvmsg` per datagram (still up to 64 per native call, so the JNI/cinterop
  crossing is batched); `KSL_UDP_GET_CAPS` never grants GSO/GRO and `IoCapabilities` reports `gsoMaxSegments = 0`,
  `gro = false`. The private `sendmsg_x`/`recvmsg_x` are not used (undocumented; quic-go does not use them either).
- **DF.** Darwin has no `IP_MTU_DISCOVER` modes: DF is `IP_DONTFRAG` on an `AF_INET` socket and `IPV6_DONTFRAG` on an
  `AF_INET6` one (which also covers the v4-mapped half of a dual-stack socket from Darwin 24 on; before, a wildcard is two
  sockets: "Dual-stack binds"), as in quic-go `sys_conn_df_darwin.go`.
  There is no `_PROBE` equivalent: Darwin caches a path MTU from an ICMPv6 Packet Too Big, clamped to at least 1280. After
  a forged PTB a datagram above the cached size fails with `EMSGSIZE`, which loses only that slot, and the PMTUD
  black-hole rule falls back to 1200; QUIC's IPv6 floor (1200 bytes of payload, 1248 with headers) stays below the clamp,
  so sending never stops. That residual is not tested (no ICMP injection on the macOS host).
- **ECN.** Marks leave as the `IP_TOS`/`IPV6_TCLASS` cmsg as on Linux; Darwin labels the received IPv4 cmsg `IP_RECVTOS`
  (one byte) rather than `IP_TOS`, and both are accepted (as in msquic and quic-go `sys_conn_helper_darwin.go`). Loopback
  keeps the marks.
- **Other details.** `fcntl(O_NONBLOCK, FD_CLOEXEC)` instead of `SOCK_CLOEXEC | SOCK_NONBLOCK`; `sin_len`/`sin6_len` set;
  `SO_NOSIGPIPE`; `SO_RCVBUF`/`SO_SNDBUF` start at 7 MB and halve until the kernel accepts them (`kern.ipc.maxsockbuf` is
  8 MB including overhead).
- **iOS.** The same C compiles for `iosArm64`/`iosSimulatorArm64`, and `bind` with a server is not refused there: nothing in
  the platform forbids a listening UDP socket in an app. Every module's suite runs on the iOS simulator; `iosArm64` is compiled and linked but has not run on a
  device.

### Windows (`mingwX64` and the JVM's JNI `.dll`)

`ksl_udp_win.c` implements the same contract for Kotlin/Native `mingwX64` and for the JVM on Windows. Options and their
order were cross-checked with msquic `src/platform/datapath_winuser.c`.

- **Send/receive.** `WSASendMsg`/`WSARecvMsg` from `SIO_GET_EXTENSION_FUNCTION_POINTER`; the socket is non-blocking and
  created with `WSA_FLAG_OVERLAPPED`, as `socket()` and msquic create theirs (the WSASocket documentation: "most sockets
  should be created with this flag set"). Without it the handle is synchronous and Windows serialises every operation on
  it: a `WSASendMsg` waited until the receiving thread's `WSAPoll` returned, so each send from the endpoint loop sat out
  up to one 100 ms receive slice. Every QUIC flight on Windows (JVM and Native) cost up to ~100 ms: an HTTP/3 request
  took ~500 ms and an 8 MiB echo ~55 s in the 4-core Windows 11 VM (`udp_win_send_while_recv_blocks`: the send now
  leaves in 0 ms instead of 1992 ms).
- **ECN** — `IP_ECN`/`IPV6_ECN` (value 50) as a socket option to read marks (cmsg on receive) and as a per-message cmsg to
  write them, as msquic does when DSCP is off. Windows 10 2004+ / Server 2022 grant it; older systems refuse the option,
  `KSL_UDP_ECN` is not granted and the core never validates ECN on that path. The granted capability is what QUIC sends,
  ECT(0), written and read back. Windows 11 refuses the CE codepoint in the `IP_ECN`/`IPV6_ECN` cmsg of `WSASendMsg`
  (`WSAEINVAL`); `ksl` then sends that datagram unmarked, sends every later CE unmarked too, and keeps ECT marking on
  for the socket (a refused ECT mark still turns ECN off for it; `udp_win_ce_send_keeps_ecn`). Before 0.2.0 a refused
  CE turned ECN off for the whole socket. That costs QUIC nothing: CE is set by routers, never by a QUIC sender (RFC 9000
  section 13.4.1, msquic and quic-go never send it), and the core's ECN validation (section 13.4.2) still judges each
  path; only a `DatagramIo` user that sends CE itself sees it leave unmarked. The portable NIO socket on the Windows
  JVM cannot mark at all: `DatagramChannel.setOption(IP_TOS)` throws `SocketException` there, so it reports
  `ecnSend = false` instead of claiming ECT(0) (`NioDatagramIoTest.portableCapabilities` and `nioSetsIpTosEct0` assert
  that pairing).
- **USO/URO** — granted only when the probe answers: `getsockopt(UDP_SEND_MSG_SIZE)` for USO (runs leave as one
  `WSASendMsg` with a `UDP_SEND_MSG_SIZE` cmsg; the run rule is Linux's), `setsockopt(UDP_RECV_MAX_COALESCED_SIZE)` for URO
  (segment size from the `UDP_COALESCED_INFO` cmsg, split into slots in C). Fallbacks: see the send-error classes.
- **DF** — `IP_DONTFRAGMENT`/`IPV6_DONTFRAG` (grants `KSL_UDP_DF`), plus `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER = PROBE`
  where the system takes it, so no path MTU cache drives sizes (quic-go CVE-2024-53259). Windows 11 (24H2 on ARM64, x64
  emulation) refuses PROBE; msquic never sets it and runs on DF alone, and `WSAEMSGSIZE` on a send loses only that slot,
  so DF alone is safe. The test checks the pairing: DF granted means `IP_DONTFRAGMENT` reads back set, and PROBE is
  required only where `ksl` recorded that the option was taken. DF is set before `bind`, as msquic does; PROBE too
  (msquic never sets it). Both go on the halves the socket carries: the IPv4 one only on an `AF_INET` socket or a
  dual-stack one on `::` (or a v4-mapped address); a socket bound to `::1` carries IPv6 alone (`udp_win_loopback6_df`).
  Observed on Windows Server 2025 (CI): a socket bound to `::1` got no DF when both halves were asked for after the
  bind, while one on `::` got both; with both changes (before the bind, the IPv6 half alone) CI run 45713491080 granted
  it DF in DO mode (Server 2025, like Windows 11, refuses PROBE there); which of the two changes cures it is not
  isolated. That socket reads `IP_DONTFRAGMENT` back set although it never asked for it, cause unknown
  (`udp_win_loopback6_df` prints it, beside two control sockets). A `0.0.0.0` socket whose dual-stack socket gets no DF
  for a lasting reason is an `AF_INET` socket instead when DF takes there, as `NioDatagramIo`'s AF_INET channel, so IPv4
  QUIC still works and IPv6 destinations are unreachable from it (`udp_win_dual_stack_without_df_takes_af_inet`). The
  dual-stack socket is closed first, so an explicit port is free; where the `AF_INET` socket does not open, or opens
  without DF for a lasting reason, the dual-stack socket is opened again (IPv6 stays reachable) and reported without DF,
  so it is not used (`udp_win_dual_stack_without_df_reopens_dual`); a transient refusal fails the open and reopens
  nothing. The tests reach these cases, on port 0 and on an explicit port, through `KSL_TEST` seams (DF refused on the
  v4-mapped half, DF refused on `AF_INET` for good or transiently, `AF_INET` sockets failing). Another process can take
  an explicit port between the close and a bind: that open then fails with `KSL_E_BIND` instead of reporting no DF.
  Since 0.3.0 a wildcard (`0.0.0.0` or `::`) asked with DF whose dual-stack socket has no DF for a lasting reason is two
  sockets on one port instead, as on Linux and Apple ("Dual-stack binds"; `open_split` in `ksl_udp_win.c`): `IPV6_V6ONLY`
  on `::` and `AF_INET` on `0.0.0.0`, both `SO_EXCLUSIVEADDRUSE`; port 0 gives up a port held for IPv4 (`WSAEADDRINUSE`,
  or `WSAEACCES` under another socket's exclusive use); a send goes through the socket of its family, a receive polls both
  (`WSAPoll`, with the wake socket) and each read prefers the other socket than the last; `KSL_UDP_V6_ONLY`,
  `KSL_UDP_V4_ONLY` or the dual-stack socket without DF where only one family or neither can have DF
  (`udp_win_df_fallback_*`, through the same seams). Windows decides after the dual-stack socket's bind, so another
  process can take an explicit port between its close and the next bind: that open fails with `KSL_E_BIND`. Built with
  `-Werror` for mingw-x64 here; run on Windows only (CI's Windows lanes, the local Windows VM).
- **Binding** — `SO_EXCLUSIVEADDRUSE`; addresses as in "Dual-stack binds" (a wildcard `0.0.0.0` is dual-stack, as on Linux
  and Apple: `udp_win_wildcard_dual_stack`, `udp_win_wildcard_without_ipv6_falls_back`); one loop per port.
- **Winsock start.** `WSAStartup(2.2)` once per process, never `WSACleanup`. ktor-network starts Winsock only when it
  creates a socket, so `InetSocketAddress.resolveAddress()` (getaddrinfo) before that failed with `WSANOTINITIALISED`
  (10093): 295 `kuicksilver-quic` tests on the first windows-2025 CI run, and any application that resolves an address
  before its first socket. The choke point is the Kotlin/Native runtime start: an `@EagerInitialization` property in
  kuicksilver-native's `mingwMain` calls `ksl_win_sockets_start(1)` before any Kotlin code of the program runs, on every
  entry path, including a caller's own resolution before it touches kuicksilver. `ksl_init` and `ksl_udp_open` start it too
  (the JVM's JNI `.dll`, C callers). Not a C constructor: in a DLL — a Kotlin/Native `sharedLib` as well as the JNI `.dll` —
  constructors run under the loader lock, where `WSAStartup` must not be called; the Kotlin/Native runtime starts on the
  first call into Kotlin, outside it. `ksl_win_sockets_started_by` records the first starter, so `WinsockReadyTest` proves
  the order whatever ran before it. `@EagerInitialization` is deprecated as a migration aid; should it go, the replacement
  is a documented call before the first address lookup. Winsock's start is reference counted: a host that calls
  `WSACleanup` once more than its own `WSAStartup` takes ksl's reference away. `ksl_udp_open` then sees
  `WSANOTINITIALISED`, forgets its once-state, starts Winsock once more and retries the socket once; sockets the cleanup
  already closed are not revived, and a lookup in between still fails until then.

### Draining before an idle close (0.3.0)

RFC 9000 section 10.1 restarts the idle timer "when a packet from its peer is received and processed successfully". A
process frozen past a connection's idle deadline wakes with the timer overdue and the peer's datagrams waiting in the
socket, or in a receive on a `Dispatchers.IO` thread that has not handed them back; fired first, the timer closed the
connection. Every socket of the library therefore implements the internal `QueuedReceive`: `receiveQueued` takes what is
queued without waiting (`ksl_udp_recv` with a zero timeout; the non-blocking `DatagramChannel`; the shared socket's
per-loop ring; ktor-network's channel), and `interruptReceive` ends a receive in flight (the NIO selector's `wakeup`, the
ring's signal, a select clause beside ktor-network's channel, and on `ksl` a flag looked at between the 100 ms wait
slices). The endpoint loop holds a connection whose idle deadline passed, with all its timers, until each receiver ran a
drain round (at most 64 datagrams) begun after the hold, and processed it; then the idle timer decides
(`runtime/EndpointLoop.idle.kt`).

The receiver itself drains, on the loop's thread, after its receive in flight returned: the socket keeps a single reader,
which `ksl_udp` requires (one receiving thread; the GRO scratch and its leftover segments belong to it), and no datagram
can sit in a receive's hands unseen while the decision is made. Rejected:

- **The timer reads the socket itself.** On `ksl` it would be a second reader beside the blocked receive on the I/O
  thread, and a datagram that receive already took (copied into its slots, not yet handed back) is in neither place
  the timer looks.
- **A non-consuming readiness probe** (`poll` with no timeout, `FIONREAD`). It is safe beside the blocked receive, but
  the same datagram taken a moment earlier by that receive escapes it; closing that gap needs `ksl` to publish when it
  takes a datagram and when the caller has it, new native API for each platform.
- **A native wake-up for the blocked receive** (writing the shutdown pipe or wake socket without closing). It would end
  the wait at once instead of with its slice, but the pipe and the Windows wake socket stand for a shutdown today, and a
  second meaning needs new native API on three receive paths. The cost of not doing it is bounded: an idle close on the
  accelerated socket can come up to one slice (100 ms) after the drain was asked, and a hold ends after 500 ms anyway.
- **Waiting for the receive in flight without interrupting it.** NIO and ktor-network wait without limit on an idle
  socket, and while one connection's close waited, every other connection's timers would have waited too.

Accepted limits: the kernel queue of a socket the loops share in process (`loops > 1` on Darwin and Windows; the
dispatcher's thread reads it, the loop drains only its ring), the kernel queue behind ktor-network's receiver on Native
(only its channel is drained), another loop's socket of a group, a caller's own `DatagramIo`, and on `ksl` an idle close up
to one 100 ms wait slice late. Nothing is sent past the idle deadline meanwhile, an application write included
(`ConnectionCore.poll` sends nothing then), so the hold cannot keep a connection the timer already ended.

### Servers on Kotlin/Native

The portable Native socket (`KtorDatagramIo`, `ktor-network`) stays client-only: its `capabilities` restrict it to the
client side, and `QuicEndpoint.bind` with a `server` on it throws `UnsupportedOperationException`
(`NativeServerGuardTest.nativeServerWithPortableIoRejected`). Since every Native target has the accelerated socket, `bind`
with a server starts on Linux, Apple and Windows (`NativeServerGuardTest.nativeServerBindsWhereTheAcceleratedIoExists`). On
Android the server also worked on NIO; `AndroidServerTest.serverOnDeviceServesLoopbackClient` (emulator API 34,
`androidConnectedCheck`) goes through the accelerated path: `ecn=Capable`, `mtu=1452`.

### Verification

- **Linux** (x64 and arm64 in Docker): `test_udp.c` — a batch of 32, GSO in one syscall + GRO splitting, two senders do not
  mix (threat-model 3.12), ECT(0)/CE arrive, PROBE mode (`udp_df_probe_mode`), an oversized datagram is dropped whole, GSO
  `EIO` → lossless fallback, two sockets on one port via REUSEPORT, shutdown wakes the receiver in < 100 ms and after it
  send/recv fail immediately, `udp_gso_run_never_starts_with_a_larger_datagram`, `udp_transient_send_errors_skip_the_datagram`,
  `udp_bad_destination_keeps_ecn_and_gso`, `udp_link_local_destination_is_slot_loss`; `KslUdpSocketTest` and
  `KslDatagramIoTest` on the JVM (a batch of 32, capabilities, GSO in one `sendmsg` by the `KSL_UDP_GET_STATS` counter, ECN on
  loopback and marks switched off after a failed validation, reuse of the address instance, `receive` woken by close,
  50 MiB through `KslQuicCrypto` with `ecnState == Capable` and `pathMtu == 1452` on both sides);
  `NativeServerLoopbackTest.nativeServerServes10MiB` in `test.kexe` x64/arm64.
- **macOS arm64:** `tools/c-test.sh macos-arm64` (the whole `test_udp.c`, with Apple variants for the caps, DF and REUSEPORT
  checks; ECT(0) and CE over IPv4, ECT(0) over IPv6); `KslUdpSocketTest`, `KslDatagramIoTest` (including 50 MiB with
  `ecnState == Capable` and `pathMtu == 1452`) on the JVM; `NativeServerLoopbackTest` (10 MiB, `ecnState == Capable`),
  `NativeServerGuardTest` and the Ktor engine's `NativeServerH3Test` on `macosArm64`.
- **Dual stack:** `udp_wildcard_is_dual_stack` (both families in and out, ECT(0)/CE, DF; macOS and Linux arm64 in Docker),
  `udp_wildcard_without_ipv6_falls_back` (a test hook fails `socket(AF_INET6)`), `KslDatagramIoTest.wildcardBindReachesBothFamilies`,
  `ClientH3Test.h3ToIpv6Loopback`; on Windows `udp_win_dual_stack`, `udp_win_wildcard_dual_stack` and
  `udp_win_wildcard_without_ipv6_falls_back`.
- **Windows:** cross-compiled on macOS with the Kotlin/Native llvm + mingw sysroot (`tools/c-test.sh mingw-x64`, `-Werror`)
  and with the Ubuntu mingw-w64 gcc 13 of the JNI build, and verified in a local Windows 11 VM (4 cores):
  `test_udp_win.c` (batch, USO in one call, two senders, ECN round trip when granted, DF probe, truncation, USO fallback,
  transient and destination errors, dual-stack, wildcard dual-stack and its IPv4 fallback, exclusive bind, wake-up
  < 100 ms, shutdown, `udp_win_send_while_recv_blocks`), kuicksilver-quic native 628/628 (with `WinsockReadyTest` and
  `NativeServerLoopbackTest.nativeServerServes10MiB`, a real Winsock server and client), kuicksilver-ktor-server native
  146/146, kuicksilver-ktor-client `ClientH3Test` 15/15 on Native and on the JVM against the JNI `.dll`. Early CI runs
  found the Winsock start defect fixed above; the GitHub Actions workflows are now disabled, and the Windows suites run
  in the VM through `tools/ci/local-matrix.sh --with-windows`.

## History

- **2026-10-02: portable side only.** `NioDatagramIo` (JVM/Android, `kuicksilver-quic/src/jvmCommonMain`) reads
  through a `DatagramChannel` with a selector, receiving datagrams in batches within one loop pass — this removed the loss
  of bursts at the socket buffer boundary found by the real-UDP tests; writes remain one datagram per call
  (`capabilities.batch = 1`). `KtorDatagramIo` (Kotlin/Native) uses `ktor-network`, client side only (see the
  cross-check), and `NativeServerGuardTest` pinned the refusal of a Native server. `PacketBuffer` got a public JVM accessor
  `asByteBuffer()` so that NIO reads and writes without copies; the import rule (ADR-0004) still lets only `PacketBuffer`
  through. The throughput of the portable path is measured as a fact, not a promise.
- **2026-10-08: accelerated UDP on Linux.** `ksl_udp_*` under `#ifdef __linux__`; on Apple `ksl_udp_open` returned `NULL` +
  `KSL_E_NOT_SUPPORTED` and the stack stayed on the portable implementation. The safe close with a blocked receiver cost
  the 57th function in `ksl.h` (`ksl_udp_shutdown`; 56 with a single `close` were planned). A Native server ran on Linux
  only; on Apple and Windows `bind` with a server threw `UnsupportedOperationException`. A separate receiver coroutine
  with a ring of two batches, as originally planned, was not needed: the endpoint loop waits on `receive` anyway.
- **Final review of the Linux socket (2026-10-08).** The GSO run rule for a larger first datagram; transient send errors lose only their
  datagram; destination `EINVAL` no longer switches ECN and GSO off forever (native-tls review), and link-local IPv6
  sources are dropped; the `KslUdpSocket` getters go through the call counter; the `EndpointLoop.close()` order
  (`RuntimeRobustnessTest.closeWaitsForTheReceiverBeforeFreeingItsBatch`, `receiveFailureClosesTheEndpoint`,
  `oneFailedSendDoesNotKillTheEndpoint`).
- **0.2.0, Apple (2026-10-13).** `ksl_udp` builds and runs on Apple (`KSL_UDP_ACCEL`); the QUIC server and the Ktor engine's
  HTTP/3 run on Kotlin/Native macOS, and the JVM on macOS uses `KslDatagramIo` by default instead of NIO. Its review made
  wildcard binds dual-stack (Linux and Apple), made `ENOBUFS` backpressure, made `EHOSTDOWN`/`ENETDOWN` a slot loss, and
  made a Darwin socket without its wake pipe fail to open.
- **0.2.0, Windows.** `ksl_udp_win.c` over Winsock; `KslUdpSocket.supported` is true on Windows, so the Native server
  guard no longer applies there and the JVM on Windows uses the accelerated socket. Its reviews made the wake socket
  exclusive, kept USO on transient errors, idled the receive on `POLLERR` and transient errors, and moved the Winsock start
  from a C constructor (which ran in static binaries only) to the Kotlin/Native runtime start, with a restart after a
  host's extra `WSACleanup`.
- **0.2.0, Windows trust and sockets (2026-10-13).** The first runs in the local Windows 11 VM found a send that
  waited behind the receiver's `WSAPoll` (sockets are now `WSA_FLAG_OVERLAPPED`), a `0.0.0.0` bind that was IPv4-only
  (now dual-stack as on Linux and Apple), a PROBE that Windows 11 refuses (DF alone, as msquic), and a NIO socket on the
  Windows JVM that claimed ECT(0) it could not send (`ecnSend = false`).
- **0.2.0, both platforms.** The `loops > 1` check moved from the platform to the `KSL_UDP_REUSEPORT` grant; a refused
  accelerated socket falls back to the portable one instead of failing the bind.
- **0.3.0, `loops > 1` everywhere.** Without the grant the loops share one socket with in-process routing by connection
  ID and a `ksl_udp_sender` clone per loop, instead of `bind` throwing `UnsupportedOperationException`.
- **0.3.0, draining before an idle close.** `QueuedReceive` on every socket of the library; the endpoint drains its sockets
  before an idle timer closes a connection (see the design section of that name).
