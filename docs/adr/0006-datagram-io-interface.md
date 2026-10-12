# ADR-0006. UDP behind the `DatagramIo` interface: portable and accelerated implementations

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

`ktor-network` and NIO offer no batched I/O, ECN, GSO/GRO or DF control. Without them QUIC on the JVM is bound by one syscall per packet and cannot do PMTUD or ECN.

## Decision

A `DatagramIo` interface with `capabilities`. Two implementations: a portable one in Kotlin (NIO on JVM/Android, `ktor-network` on Native) and an accelerated native one in `ksl` (Linux/Android: `sendmmsg`/`recvmmsg`, GSO/GRO, ECN, DF; Apple: `sendmsg` + ECN; Windows: `WSASendMsg`). If the accelerated one is unavailable, the portable one is used; the transport enables ECN/GSO according to `capabilities`.

Cross-check 2026-10-02: `ktor-network` on Native closes receiving forever on an empty datagram and copies every packet, so the portable implementation on Native is only good for a client; a Native server requires the accelerated path. The main acceleration axis is GSO (`sendmsg` + `UDP_SEGMENT`, as in quinn/quic-go/ngtcp2), `sendmmsg` is secondary; DF is set when the socket is created (`IP_PMTUDISC_PROBE`), ECN on the JVM is send-only ECT(0); Android 12+ offers an intermediate path through `android.system.Os`.

## Consequences

- The transport does not depend on the platform socket; active migration is simply a new `DatagramIo`.
- The native surface grows by ~6 functions.

## Implementation in K2

K2 implements only the portable side of the `DatagramIo` interface; the accelerated path (`sendmmsg`/`recvmmsg`, GSO/GRO, ECN, DF in `ksl`) and the `linuxX64` server image are left to K3.

- `NioDatagramIo` (JVM/Android, `kuicksilver-quic/src/jvmCommonMain`) reads through a `DatagramChannel` with a selector, receiving datagrams in batches within one loop pass (`receive()` may return several packets without waiting in between) — this removed the loss of bursts at the socket buffer boundary found by the real-UDP tests. Writes remain one datagram per call (`capabilities.batch = 1`); batched sending is part of the accelerated path.
- `KtorDatagramIo` (Kotlin/Native, `src/nativeMain`) uses `ktor-network`; its `capabilities` restrict it to the client side. The reason is the fact recorded in the 2026-10-02 cross-check: `ktor-network` on Native closes receiving forever after an empty datagram and copies every packet, so a Native server needs an accelerated `DatagramIo`, which K2 does not have (`NativeServerGuardTest` pins the refusal when a server is started on this transport).
- `PacketBuffer` (from `kuicksilver-native`) got a public JVM accessor `asByteBuffer()` (a duplicate `ByteBuffer` view of the direct memory) so that NIO reads and writes without copies; the import rule (ADR-0004) still lets only `PacketBuffer` through.
- The throughput of the portable path (MiB/s on JVM and linuxX64) is measured as a fact, not a promise.

## Implementation in K3 — accelerated UDP in `ksl`

The accelerated side lives in `ksl` as `ksl_udp_*` (`kuicksilver-native/src/c/ksl_udp.c`, `ksl_udp_send.c`, `ksl_udp_recv.c`, `#ifdef __linux__` only; on Apple/Windows `ksl_udp_open` returns `NULL` + `KSL_E_NOT_SUPPORTED`, and the stack stays on the portable implementation). The wrapper is `io.kuicksilver.tls.KslUdpSocket` (common code over `Ksl.udp*`, JNI and cinterop), connected to `DatagramIo` as described below.

- **One socket, batches.** `ksl_udp_send`/`ksl_udp_recv` take up to `KSL_UDP_MAX_BATCH` (64) slots — `PacketBuffer`s that C reads and writes in place: not a single copy in Kotlin, not a single allocation in C after `open` (addresses, lengths and ECN marks are fixed-size arrays on the stack of the JNI call). Slots with the same address, the same mark and the same length (the last one may be shorter) go out in one `sendmsg` with `UDP_SEGMENT`; receiving is `recvmsg` with `UDP_GRO` into a 64 KiB buffer, the segments are spread over the slots inside C, the remainder waits for the next call (`PacketBatch`/`handleDatagram` see no offsets).
- **Lossless fallbacks.** `EIO`/`ENOTSUP` on a GSO send switch GSO off for the socket forever and send the segments one by one; `EINVAL` on GSO switches it off only if the first segment then goes out alone; `EINVAL` on a single send with a mark is retried without the `IP_TOS` cmsg, and the cmsg is switched off only if the retry went out; destination errors (`EINVAL`, `EAFNOSUPPORT`, `EADDRNOTAVAIL`, `EDESTADDRREQ`: port 0, link-local IPv6) lose only the slot; the first `EPERM` gets one retry; `EMSGSIZE` skips only that slot (it counts as sent, kernel PMTUD learns from the loss) and is never a socket error; `EAGAIN` is `KSL_OK` with a partial `sent`. What the kernel actually granted is read from `KSL_UDP_GET_CAPS` (flags | gso max | batch) — `KslUdpSocket.grantedFlags` after a short send.
- **ECN and DF.** The per-datagram mark is the `IP_TOS`/`IPV6_TCLASS` cmsg (not `setsockopt`, so a batch with different marks does not cost extra syscalls), receiving through `IP_RECVTOS`/`IPV6_RECVTCLASS`. DF is `IP_PMTUDISC_PROBE` + `IPV6_DONTFRAG`, never `_DO` (the kernel does not substitute the size from its PMTU cache, and a forged ICMP PTB does not break sending: quic-go CVE-2024-53259). `SO_RCVBUF`/`SO_SNDBUF` 7 MB, `SO_REUSEPORT` by flag.
- **Shutdown from another thread.** `ksl_udp_shutdown` wakes a blocked `ksl_udp_recv` (a pipe in `poll`) and closes the fd; `ksl_udp_close` frees the object after the receiver has left. `KslUdpSocket` keeps the count of threads inside a native call and the shutdown flag in one atomic: entering after shutdown is impossible, `close` frees memory only at a zero count — a use-after-free between the check and the call is ruled out. This cost the 57th function in `ksl.h` (56 with a single `close` were planned): without a separate wake-up, a safe close with a blocked receiver is impossible.
- **Verification.** `test_udp.c` (Linux x64/arm64 in Docker; on macOS only the `NOT_SUPPORTED` refusal): a batch of 32, GSO in one syscall + GRO splitting, two senders do not mix (threat-model 3.12), ECT(0)/CE arrive, PROBE mode, an oversized datagram is dropped whole, GSO `EIO` → lossless fallback, two sockets on one port via REUSEPORT, shutdown wakes the receiver in < 100 ms and after it send/recv fail immediately. `KslUdpSocketTest` (jvmTest via `docker-jvm.sh`): `openSendReceive`, `grantedFlagsOnLinux`, `closeUnblocksReceive`, `openOnUnsupportedPlatformThrows`.

### `KslDatagramIo` and servers on Native and Android

- `KslDatagramIo` (`kuicksilver-quic/src/commonMain`, common code) is a `DatagramIo` over `KslUdpSocket`: `PacketBatch` slots go to C as they are; `receive` blocks a `Dispatchers.IO` thread in 100 ms slices until the first datagram or close (like the NIO implementation with a selector; a separate receiver coroutine with a ring of two batches, as originally planned, is not needed — the endpoint loop waits on `receive` anyway); peer addresses are a 64-entry cache keyed by the 20 bytes → one `InetSocketAddress` instance per peer (the core compares paths by reference), destination addresses are a cache of the last 4 by identity. `capabilities` (`StateFlow`) are re-read from `KSL_UDP_GET_CAPS` every 256 sends and after a short send: a GSO/ECN fallback in C shows up in them with that delay, the datagrams themselves are not lost during the fallback.
- `DatagramIo.open(local, prefer = Accelerated)` returns `KslDatagramIo` where `KslUdpSocket.supported` (Linux JVM/Native, Android; from K7 also Apple JVM/Native), otherwise the portable one; `IoPreference.Portable` always returns the portable one (NIO tests request it explicitly).
- A server on Native is allowed only with the accelerated transport: `QuicEndpoint.bind` with `server` on Apple/Windows still throws `UnsupportedOperationException` (`NativeServerGuardTest`), on Linux it starts a server (`NativeServerLoopbackTest.nativeServerServes10MiB`, `test.kexe` x64/arm64 in Docker). On Android the server also worked on NIO; `AndroidServerTest.serverOnDeviceServesLoopbackClient` (emulator API 34, `androidConnectedCheck`) goes through the accelerated path: `ecn=Capable`, `mtu=1452`.
- Verification on the JVM: `KslDatagramIoTest` (Linux in Docker, both architectures): a batch of 32, capabilities, GSO in one `sendmsg` (the `KSL_UDP_GET_STATS` counter), ECN on loopback and switching marks off after a failed validation, reuse of the address instance, waking `receive` by close, 50 MiB through `KslQuicCrypto` with `ecnState == Capable` and `pathMtu == 1452` on both sides.

### Fixes from the final K3 review (2026-10-08)

- `ksl_udp_send`: a GSO run starts only with two equal lengths — a datagram larger than the following ones (a PMTU probe) does not set the `gso_size` of the whole run (on a narrow link the kernel answers EINVAL, and GSO was switched off forever); EINVAL/EMSGSIZE for a run with a segment > 1200 resends one by one without switching GSO off. Transient send errors (EPERM after one retry, EACCES, ENETUNREACH, EHOSTUNREACH, ENOBUFS, ENOMEM, ECONNREFUSED) lose only that datagram, the socket lives on; the EPERM retry budget is restored after a successful send. Tests: `udp_gso_run_never_starts_with_a_larger_datagram`, `udp_transient_send_errors_skip_the_datagram`.
- native-tls review: `EINVAL` caused by the destination (a reply to a forged Initial from port 0, a link-local IPv6 peer — the 20-byte address has no scope id) was read as the kernel refusing the `IP_TOS` cmsg or GSO: ECN and GSO were switched off forever, and a second `EINVAL` produced `KSL_ERROR`, and `EndpointLoop` lost the rest of the batch. Now a repeated single send (without a mark, without GSO) decides the cause, and destination errors are a slot loss; link-local IPv6 is not supported: `ksl_udp_recv` drops datagrams from `fe80::/10`. Tests (Linux): `udp_bad_destination_keeps_ecn_and_gso`, `udp_link_local_destination_is_slot_loss`.
- `KslUdpSocket`: the getters `grantedFlags`/`gsoMaxSegments`/`batch`/`stats` enter the native object through the same counter as `send`/`receive`, and after `shutdown` return the last value read (use-after-free ruled out).
- `EndpointLoop.close()`: the socket is closed first (waking a receive blocked in a native call), the receiver is awaited, and only then are the `PacketBatch`es freed — on Native the receive writes into their memory (`RuntimeRobustnessTest.closeWaitsForTheReceiverBeforeFreeingItsBatch`); a receive error closes the whole endpoint; a send error loses the packet, not the connection (`receiveFailureClosesTheEndpoint`, `oneFailedSendDoesNotKillTheEndpoint`).

## Implementation in K7 — accelerated UDP on Apple (2026-10-13)

`ksl_udp_*` now builds and runs on Apple (`#if defined(__linux__) || defined(__APPLE__)`, `KSL_UDP_ACCEL` in
`ksl_udp_internal.h`); only Windows keeps the `KSL_E_NOT_SUPPORTED` stubs. So a QUIC server runs on Kotlin/Native macOS
(the `NativeServerGuardTest` refusal remains for Windows), the Ktor engine serves HTTP/3 there, and the JVM on macOS uses
`KslDatagramIo` by default instead of NIO (ECN read and written per datagram, DF, so PMTUD reaches 1452 on loopback).

- **No GSO/GRO.** Darwin has no `UDP_SEGMENT`/`UDP_GRO`. The run-joining code is not compiled there, a batch leaves as one
  `sendmsg` per datagram and arrives as one `recvmsg` per datagram (still up to 64 per native call, so the JNI/cinterop
  crossing is batched); `KSL_UDP_GET_CAPS` never grants GSO/GRO and `IoCapabilities` reports `gsoMaxSegments = 0`,
  `gro = false`. The private `sendmsg_x`/`recvmsg_x` are not used (undocumented; quic-go does not use them either).
- **`poll`, not kqueue.** A receive waits on two descriptors, the socket and the shutdown pipe, from a blocking slice of
  at most 100 ms on its own `Dispatchers.IO` thread. kqueue pays off when one thread multiplexes many sockets (msquic
  `datapath_kqueue.c` runs its own event loop over every socket of the process); here it would add a kqueue descriptor
  per socket and a second receive loop for the same two-descriptor wait, while `poll` is POSIX and keeps one receive path
  for Linux and Apple.
- **DF.** Darwin has no `IP_MTU_DISCOVER` modes: DF is `IP_DONTFRAG` (IPv4) or `IPV6_DONTFRAG` (the socket is
  IPv6-only), as in quic-go `sys_conn_df_darwin.go`. There is no `_PROBE` equivalent; should the kernel ever refuse a
  size after a forged ICMP PTB (the CVE-2024-53259 shape on Linux `_DO`), `EMSGSIZE` loses only that slot and the PMTUD
  black-hole rule falls back to 1200 — a residual that is not tested (no ICMP injection on the macOS host).
- **ECN.** Marks leave as the `IP_TOS`/`IPV6_TCLASS` cmsg as on Linux; Darwin labels the received IPv4 cmsg `IP_RECVTOS`
  (one byte) rather than `IP_TOS`, and both are accepted (as in msquic and quic-go `sys_conn_helper_darwin.go`). Loopback
  keeps the marks: `test_udp.c` checks ECT(0) and CE over IPv4 and ECT(0) over IPv6, and `NativeServerLoopbackTest`
  ends with `ecnState == Capable` on `macosArm64`.
- **No `SO_REUSEPORT`.** Darwin accepts the option but hands a port's unicast datagrams to one of the sockets (the last
  bound), with no flow hashing: with four loops, `MultiLoopTest` saw 100 of 100 connections on one loop. `ksl_udp` never
  sets or grants `KSL_UDP_REUSEPORT` there and `LoopGroup` refuses `loops > 1` with `UnsupportedOperationException`.
- **Other Darwin details.** `pipe` + `fcntl(O_NONBLOCK, FD_CLOEXEC)` instead of `pipe2`, the same for the socket instead
  of `SOCK_CLOEXEC | SOCK_NONBLOCK`; `sin_len`/`sin6_len` set; `SO_NOSIGPIPE`; `SO_RCVBUF`/`SO_SNDBUF` start at 7 MB and
  halve until the kernel accepts them (`kern.ipc.maxsockbuf` is 8 MB including overhead).
- **iOS.** The same C compiles for `iosArm64`/`iosSimulatorArm64`, and `bind` with a server is not refused there: nothing
  in the platform forbids a listening UDP socket in an app. iOS is compiled and linked only; its tests have not run.
- **Wildcard binds are dual-stack (review of k7/macos-server).** A `0.0.0.0` bind used to open an `AF_INET` socket and
  every IPv6 socket was `IPV6_V6ONLY`, while NIO's `DatagramChannel.open()` is dual-stack with `0.0.0.0` taken as `::`:
  the Ktor client's endpoint on `0.0.0.0:0` could not reach an IPv6 h3 server (the slot was lost, the handshake timed out)
  and a Ktor server on the default host answered HTTP/3 over IPv4 only while its TCP listener took IPv6. Now, on Linux and
  Apple, a wildcard (`0.0.0.0` or `::`) opens one `AF_INET6` socket bound to `::` with `IPV6_V6ONLY = 0`; an IPv4
  destination leaves as `::ffff:a.b.c.d`, a v4-mapped source is reported as IPv4 (family 4), and a `0.0.0.0` request
  still reports `0.0.0.0` as its local address (Windows does the same in `ksl_udp_win.c`). A specific address keeps its
  own family, IPv6 ones stay `IPV6_V6ONLY`. When the dual-stack socket cannot be made (no IPv6 in the kernel, `::` taken)
  `0.0.0.0` falls back to the `AF_INET` socket of before. ECN and DF cover both halves: the outgoing mark's cmsg follows
  the destination (`IP_TOS` for IPv4: Linux ignores `IPV6_TCLASS` for a v4-mapped peer); Linux sets `IP_RECVTOS` and
  `IP_MTU_DISCOVER = PROBE` on the `AF_INET6` socket for the v4-mapped half beside `IPV6_RECVTCLASS`/`IPV6_MTU_DISCOVER`;
  Darwin refuses `IP_RECVTOS` and `IP_DONTFRAG` there (`EINVAL`) but `IPV6_RECVTCLASS` reports v4-mapped marks and
  `IPV6_DONTFRAG` sets DF on v4-mapped datagrams (a 20000-byte datagram to `127.0.0.1` over `lo0`, MTU 16384, fails with
  `EMSGSIZE`). Tests: `udp_wildcard_is_dual_stack` (both families in and out, ECT(0)/CE, DF; macOS and Linux arm64 in
  Docker), `udp_wildcard_without_ipv6_falls_back` (a test hook fails `socket(AF_INET6)`),
  `KslDatagramIoTest.wildcardBindReachesBothFamilies`, `ClientH3Test.h3ToIpv6Loopback`.
- **Verification (macOS arm64).** `tools/c-test.sh macos-arm64` (the whole `test_udp.c`, with Apple variants for the
  caps, DF and REUSEPORT checks); `KslUdpSocketTest`, `KslDatagramIoTest` (incl. 50 MiB with `ecnState == Capable` and
  `pathMtu == 1452`) on the JVM; `NativeServerLoopbackTest` (10 MiB), `NativeServerGuardTest`, and the Ktor engine's
  `NativeServerH3Test` on `macosArm64`.
