# ADR-0006. UDP behind the `DatagramIo` interface: portable and accelerated implementations

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02). Implemented in K2 (portable side), K3 (accelerated
Linux and Android) and K7 / 0.2.0 (accelerated Apple and Windows, 2026-10-13); the history is at the end.

## Context

`ktor-network` and NIO offer no batched I/O, ECN, GSO/GRO or DF control. Without them QUIC on the JVM is bound by one syscall per packet and cannot do PMTUD or ECN.

## Decision

A `DatagramIo` interface with `capabilities`. Two implementations: a portable one in Kotlin (NIO on JVM/Android, `ktor-network` on Native) and an accelerated native one in `ksl` (Linux/Android: `sendmmsg`/`recvmmsg`, GSO/GRO, ECN, DF; Apple: `sendmsg` + ECN; Windows: `WSASendMsg`). If the accelerated one is unavailable, the portable one is used; the transport enables ECN/GSO according to `capabilities`.

As built (0.2.0): Linux/Android batch `sendmsg` with `UDP_SEGMENT` runs and `recvmsg` with `UDP_GRO` (GSO carries the batching, so `sendmmsg` was not needed); Apple `sendmsg`/`recvmsg` per datagram with ECN and DF; Windows `WSASendMsg`/`WSARecvMsg` with USO/URO, ECN and DF where the system grants them. The transport also enables PMTUD according to the DF grant.

Cross-check 2026-10-02: `ktor-network` on Native closes receiving forever on an empty datagram and copies every packet, so the portable implementation on Native is only good for a client; a Native server requires the accelerated path. The main acceleration axis is GSO (`sendmsg` + `UDP_SEGMENT`, as in quinn/quic-go/ngtcp2), `sendmmsg` is secondary; DF is set when the socket is created (`IP_PMTUDISC_PROBE`), ECN on the JVM is send-only ECT(0); Android 12+ offers an intermediate path through `android.system.Os`.

## Consequences

- The transport does not depend on the platform socket; active migration is simply a new `DatagramIo`.
- The native surface grows by a handful of `ksl_udp_*` functions (57 functions in `ksl.h` after K3, see the history).
- Every target of the library has the accelerated socket since 0.2.0, so a QUIC server runs on all of them; the portable
  socket remains the fallback and the explicit choice (`IoPreference.Portable`).

## Design as of 0.2.0

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
- **`KslDatagramIo`** (`kuicksilver-quic/src/commonMain`) is the `DatagramIo` over `KslUdpSocket`: `PacketBatch` slots go
  to C as they are; `receive` blocks a `Dispatchers.IO` thread in 100 ms slices until the first datagram or close. While
  datagrams keep coming the endpoint loop reads it on its own thread instead (`receiveNow`, `runtime/BatchReceiver.kt`):
  what is queued, or what arrives within 1 ms and before the loop's next timer, and the loop's queued work still runs after
  every 16 datagrams or 1 ms; the hand-off to an I/O thread and back cost more CPU than the QUIC work of a batch of a few
  datagrams (0.2.1, docs/benchmarks.md). `ksl_udp_recv` calls `recvmsg` first and polls only on an empty queue (not on Windows); peer
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
   backpressure since the review of k7/macos-server). `KSL_OK` with a partial `sent`; the caller sends the rest later.
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

NIO's `DatagramChannel.open()` is dual-stack and takes `0.0.0.0` as `::`; the accelerated socket matches it (review of
k7/macos-server). On Linux and Apple a wildcard (`0.0.0.0` or `::`) opens one `AF_INET6` socket bound to `::` with
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
but `IPV6_RECVTCLASS` reports v4-mapped marks and `IPV6_DONTFRAG` sets DF on v4-mapped datagrams (a 20000-byte datagram to
`127.0.0.1` over `lo0`, MTU 16384, fails with `EMSGSIZE`).

Windows differs in one point: every IPv6 socket is dual-stack (`IPV6_V6ONLY = 0`, also for a specific IPv6 address), with
v4 peers reported and addressed as family 4 (v4-mapped inside C). A wildcard `0.0.0.0` opens the dual-stack socket on `::`
on the requested port (`udp_win_wildcard_explicit_port_kept`) and reports `0.0.0.0` with that port, as on Linux and Apple, so the Ktor client's `0.0.0.0:0` endpoint reaches IPv6
servers; without IPv6 it falls back to `AF_INET` (before the 0.2.0 Windows fixes, `0.0.0.0` gave an IPv4-only socket
there).

### `SO_REUSEPORT` grant and `loops > 1`

Several endpoint loops on one port (`LoopGroup`) need kernel flow hashing over `SO_REUSEPORT` sockets. `ksl_udp` sets
`SO_REUSEPORT` only when asked and reports `KSL_UDP_REUSEPORT` only when the kernel took it. `LoopGroup` checks that grant
on the first socket (through an injectable opener) and, without it, throws `UnsupportedOperationException` before
binding a second socket (before 0.2.0 the second bind failed with `KslException.Internal`). The check is the grant, not the
platform, so it covers:

- **Apple:** Darwin accepts the option but hands a port's unicast datagrams to one of the sockets (the last bound), with
  no flow hashing: with four loops, `MultiLoopTest` saw 100 of 100 connections on one loop. `ksl_udp` never sets or
  grants `KSL_UDP_REUSEPORT` there.
- **Windows:** the socket is bound with `SO_EXCLUSIVEADDRUSE` (Windows `SO_REUSEADDR` would let another socket take the
  port over, msquic does the same), so `KSL_UDP_REUSEPORT` is never granted.
- **Linux** with a seccomp filter that refuses `SO_REUSEPORT`.

`loops > 1` therefore runs on Linux and Android only.

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

### Apple (macOS, iOS)

- **No GSO/GRO.** Darwin has no `UDP_SEGMENT`/`UDP_GRO`. The run-joining code is not compiled there; a batch leaves as one
  `sendmsg` per datagram and arrives as one `recvmsg` per datagram (still up to 64 per native call, so the JNI/cinterop
  crossing is batched); `KSL_UDP_GET_CAPS` never grants GSO/GRO and `IoCapabilities` reports `gsoMaxSegments = 0`,
  `gro = false`. The private `sendmsg_x`/`recvmsg_x` are not used (undocumented; quic-go does not use them either).
- **DF.** Darwin has no `IP_MTU_DISCOVER` modes: DF is `IP_DONTFRAG` on an `AF_INET` socket and `IPV6_DONTFRAG` on an
  `AF_INET6` one (which also covers the v4-mapped half of a dual-stack socket), as in quic-go `sys_conn_df_darwin.go`.
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
  the platform forbids a listening UDP socket in an app. iOS is compiled and linked only; its tests have not run.

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
- **DF** — `IP_DONTFRAGMENT`/`IPV6_DONTFRAG` (grants `KSL_UDP_DF`), plus `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER = PROBE` where
  the system takes it, so no path MTU cache drives sizes (quic-go CVE-2024-53259). Windows 11 (24H2 on ARM64, x64
  emulation) refuses PROBE; msquic never sets it and runs on DF alone, and `WSAEMSGSIZE` on a send loses only that slot,
  so DF alone is safe. The test checks the pairing: DF granted means `IP_DONTFRAGMENT` reads back set, and PROBE is
  required only where `ksl` recorded that the option was taken.
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
  and with the Ubuntu mingw-w64 gcc 13 of the JNI build, and verified on the owner's local Windows 11 VM (4 cores):
  `test_udp_win.c` (batch, USO in one call, two senders, ECN round trip when granted, DF probe, truncation, USO fallback,
  transient and destination errors, dual-stack, wildcard dual-stack and its IPv4 fallback, exclusive bind, wake-up
  < 100 ms, shutdown, `udp_win_send_while_recv_blocks`), kuicksilver-quic native 628/628 (with `WinsockReadyTest` and
  `NativeServerLoopbackTest.nativeServerServes10MiB`, a real Winsock server and client), kuicksilver-ktor-server native
  146/146, kuicksilver-ktor-client `ClientH3Test` 15/15 on Native and on the JVM against the JNI `.dll`. Early CI runs
  found the Winsock start defect fixed above; GitHub Actions is not used for Windows.

## History

- **K2 (2026-10-02): portable side only.** `NioDatagramIo` (JVM/Android, `kuicksilver-quic/src/jvmCommonMain`) reads
  through a `DatagramChannel` with a selector, receiving datagrams in batches within one loop pass — this removed the loss
  of bursts at the socket buffer boundary found by the real-UDP tests; writes remain one datagram per call
  (`capabilities.batch = 1`). `KtorDatagramIo` (Kotlin/Native) uses `ktor-network`, client side only (see the
  cross-check), and `NativeServerGuardTest` pinned the refusal of a Native server. `PacketBuffer` got a public JVM accessor
  `asByteBuffer()` so that NIO reads and writes without copies; the import rule (ADR-0004) still lets only `PacketBuffer`
  through. The throughput of the portable path is measured as a fact, not a promise.
- **K3: accelerated UDP on Linux.** `ksl_udp_*` under `#ifdef __linux__`; on Apple `ksl_udp_open` returned `NULL` +
  `KSL_E_NOT_SUPPORTED` and the stack stayed on the portable implementation. The safe close with a blocked receiver cost
  the 57th function in `ksl.h` (`ksl_udp_shutdown`; 56 with a single `close` were planned). A Native server ran on Linux
  only; on Apple and Windows `bind` with a server threw `UnsupportedOperationException`. A separate receiver coroutine
  with a ring of two batches, as originally planned, was not needed: the endpoint loop waits on `receive` anyway.
- **K3 final review (2026-10-08).** The GSO run rule for a larger first datagram; transient send errors lose only their
  datagram; destination `EINVAL` no longer switches ECN and GSO off forever (native-tls review), and link-local IPv6
  sources are dropped; the `KslUdpSocket` getters go through the call counter; the `EndpointLoop.close()` order
  (`RuntimeRobustnessTest.closeWaitsForTheReceiverBeforeFreeingItsBatch`, `receiveFailureClosesTheEndpoint`,
  `oneFailedSendDoesNotKillTheEndpoint`).
- **K7, Apple (2026-10-13).** `ksl_udp` builds and runs on Apple (`KSL_UDP_ACCEL`); the QUIC server and the Ktor engine's
  HTTP/3 run on Kotlin/Native macOS, and the JVM on macOS uses `KslDatagramIo` by default instead of NIO. Its review made
  wildcard binds dual-stack (Linux and Apple), made `ENOBUFS` backpressure, made `EHOSTDOWN`/`ENETDOWN` a slot loss, and
  made a Darwin socket without its wake pipe fail to open.
- **K7, Windows (0.2.0).** `ksl_udp_win.c` over Winsock; `KslUdpSocket.supported` is true on Windows, so the Native server
  guard no longer applies there and the JVM on Windows uses the accelerated socket. Its reviews made the wake socket
  exclusive, kept USO on transient errors, idled the receive on `POLLERR` and transient errors, and moved the Winsock start
  from a C constructor (which ran in static binaries only) to the Kotlin/Native runtime start, with a restart after a
  host's extra `WSACleanup`.
- **K7, Windows trust and sockets (win-trust, 2026-10-13).** The first runs in the local Windows 11 VM found a send that
  waited behind the receiver's `WSAPoll` (sockets are now `WSA_FLAG_OVERLAPPED`), a `0.0.0.0` bind that was IPv4-only
  (now dual-stack as on Linux and Apple), a PROBE that Windows 11 refuses (DF alone, as msquic), and a NIO socket on the
  Windows JVM that claimed ECT(0) it could not send (`ecnSend = false`).
- **K7, both platforms.** The `loops > 1` check moved from the platform to the `KSL_UDP_REUSEPORT` grant; a refused
  accelerated socket falls back to the portable one instead of failing the bind.
