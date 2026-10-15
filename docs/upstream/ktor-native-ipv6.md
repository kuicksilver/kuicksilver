<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Draft: Ktor issue "Kotlin/Native sockets bind and connect every IPv6 address as `::`"

Status: **draft, not filed**. Filing it is the owner's decision. Where: [YouTrack, project KTOR](https://youtrack.jetbrains.com/newIssue?project=KTOR)
(Ktor's GitHub issues are disabled and point there), subsystem *Network* / *Sockets*. Ktor's
[CONTRIBUTING.md](https://github.com/ktorio/ktor/blob/main/CONTRIBUTING.md#reporting-issues) asks for: a search for
duplicates, a test against the latest release, the platform and OS, a complete minimal reproducer, expected versus actual
behaviour. Its [AI policy](https://github.com/ktorio/ktor/blob/main/AI_POLICY.md) allows a tool-assisted issue
description if it is labelled as such (it strongly recommends writing it yourself) and asks that comments in the
discussion are not written with AI tools.

This is security-relevant (a loopback-only listener is reachable from the network, client traffic for a remote IPv6 host
is delivered to a local process). Consider reporting it privately first ([JetBrains security
disclosure](https://www.jetbrains.com/privacy-security/)) rather than in a public issue; the owner decides.

Duplicate search (2026-10-13 and 2026-10-15, YouTrack KTOR, queries `IPv6`, `IPv6 native`, `sockaddr_in6`,
`NativeIPv6SocketAddress`, `IPv6 bind ::`, `IPv6 Windows 10049`): no report of this.
[KTOR-9532](https://youtrack.jetbrains.com/issue/KTOR-9532) (iOS, UDP "Operation not permitted" on the EE network in the
UK, open) may have this root cause: EE is an IPv6-only (464XLAT) network, where a UDP connect goes to an IPv6 address;
that is not verified, so a pointer comment there is optional.

Kuicksilver works around it in its own code (see "Workaround in Kuicksilver" at the end). Everything above the line below
is context for the owner; the text below the line is the proposed issue.

---

**Title:** Native: IPv6 socket addresses are bound and connected as `::` (address bytes never copied into `sockaddr_in6`)

**Summary.** `NativeIPv6SocketAddress.nativeAddress` builds the `sockaddr_in6` passed to `bind`, `connect` and `sendto`
from family, port, flow info and scope id, but never copies the 16 address bytes (`sin6_addr`), so the kernel always gets
`::` (the unspecified address). The IPv4 twin copies `sin_addr` correctly.

- A TCP or UDP socket bound to a specific IPv6 address (`::1`, a global address) is bound to `::` instead: it listens on
  **every** IPv6 interface, and on Linux and Apple (where `IPV6_V6ONLY` is off by default) on every IPv4 address too.
  `localAddress` honestly reports `::`.
- A TCP connect, a connected UDP socket or a datagram to any IPv6 address goes to `::`. Linux and Apple route that to
  the local host, so the connection reaches whatever local process holds that port (a cleartext `http://[2001:db8::1]:8080`
  request is answered by a local listener on 8080; with TLS, host-name verification fails instead). Windows refuses it with
  `WSAEADDRNOTAVAIL` (10049), so IPv6 does not work at all there.

This is security-relevant: a server configured for `::1` only (a loopback admin endpoint) is reachable from the network,
and client traffic meant for a remote IPv6 host is delivered to a local process.

**Environment.** ktor-network on every Kotlin/Native target: Linux, Apple (macOS, iOS, tvOS, watchOS), Windows
(mingwX64, since native Windows support in 3.0.0), Android Native. Observed with 3.6.0 on macOS 26 (macosArm64) and
Windows 11 (mingwX64); the code is the same on `main` (`4016bdfe`, 2026-10-12) and in every release since 1.4.0 (see
"History"). JVM and JS are not affected. Engine: none, plain `aSocket(selector).tcp()`; every Native user of
ktor-network sockets (the CIO client and server among them) goes through the same code.

**Steps to reproduce** (Kotlin/Native, any target with an IPv6 loopback):

```kotlin
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val selector = SelectorManager(Dispatchers.Default)
    val server = aSocket(selector).tcp().bind("::1", 0)
    val port = server.localAddress.port()
    println(server.localAddress)  // expected hostname "::1"; prints "::"

    // Linux, macOS: the "::1" listener accepts an IPv4 connection (it is bound to the dual-stack wildcard)
    println(runCatching { aSocket(selector).tcp().connect("127.0.0.1", port) })   // expected: connection refused

    // Linux, macOS: a connect to an address where nothing listens reaches the local listener instead
    println(runCatching { aSocket(selector).tcp().connect("::ffff:127.0.0.2", port) })   // expected: refused or no route

    // Windows: fails with WSAEADDRNOTAVAIL (10049) although the listener exists
    println(runCatching { aSocket(selector).tcp().connect("::1", port) })
}
```

**Expected.** The listener is bound to `::1` (and reports it); an IPv4 connect to its port is refused; a connect to an
address where nothing listens is refused or unreachable; a connect to `[::1]:<port>` reaches the listener on every
platform.

**Actual.** macOS 26 (macosArm64), Ktor 3.6.0: the listener bound to `::1` reports `::` and accepts `127.0.0.1:<port>`;
a request to `[::ffff:127.0.0.1]:<port>` (nothing listens there) is answered by the `::1` listener. Windows 11
(mingwX64), Ktor 3.6.0: the connect to `[::1]:<port>` fails with `POSIX error 10049`. (Linux was not run with this
reproducer; it shares the macOS code path, `ktor-network/nix`.)

**Root cause.** [NativeSocketAddressNix.kt#L63-L72](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/nix/src/io/ktor/network/util/NativeSocketAddressNix.kt#L63-L72)
(tag 3.6.0), and the same code in
[NativeSocketAddressWindows.kt#L66-L75](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/windows/src/io/ktor/network/util/NativeSocketAddressWindows.kt#L66-L75):

```kotlin
actual override fun nativeAddress(block: (address: CPointer<sockaddr>, size: UInt) -> Unit) {
    cValue<sockaddr_in6> {
        sin6_family = family.convert()
        sin6_flowinfo = flowInfo
        sin6_port = hostToNetworkOrder(port.toUShort())
        sin6_scope_id = scopeId
        // sin6_addr is never set: `rawAddress` (a CValue<in6_addr>) is only used by ipString / rawAddressBytes
        block(ptr.reinterpret(), sizeOf<sockaddr_in6>().convert())
    }
}
```

`nativeAddress` is what every native socket operation uses: `tcpBind` and `tcpConnect`
([ConnectUtilsNative.kt#L70](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/posix/src/io/ktor/network/sockets/ConnectUtilsNative.kt#L70),
[TCPSocketNative.kt#L28](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/posix/src/io/ktor/network/sockets/TCPSocketNative.kt#L28)),
`udpBind` and `udpConnect`
([UDPSocketBuilderNative.kt#L29](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/posix/src/io/ktor/network/sockets/UDPSocketBuilderNative.kt#L29),
[#L33](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/posix/src/io/ktor/network/sockets/UDPSocketBuilderNative.kt#L33),
[#L62](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/posix/src/io/ktor/network/sockets/UDPSocketBuilderNative.kt#L62))
and datagram sends
([DatagramSendChannel.kt#L111](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/posix/src/io/ktor/network/sockets/DatagramSendChannel.kt#L111)).

**History.** Present since 1.4.0 (August 2020): commit [9785a7a82](https://github.com/ktorio/ktor/commit/9785a7a82)
("Add native-mt support for CIO client") introduced `IPv6Address.nativeAddress` in
`ktor-network/posix/src/io/ktor/network/util/SocketAddress.kt` with the copy of the address bytes commented out
(`// sin6_addr.__u6_addr.__u6_addr8[index] = byte.convert()`). The code moved to `NativeSocketAddress.kt` (2.x) and
`NativeSocketAddressNix.kt` / `NativeSocketAddressWindows.kt` (3.0.0, [962550ba0](https://github.com/ktorio/ktor/commit/962550ba0),
native Windows support) without ever setting `sin6_addr`; it is the same in 2.3.13, every 3.x release and `main`.

**Impact.** A server bound to a specific IPv6 address listens on every address, IPv4 included on Linux and Apple
(a `::1`-only admin endpoint is reachable from the network); client connections and datagrams to any IPv6 host go to the
local host on Linux and Apple (to whatever local process holds that port), and fail on Windows. IPv6 networking on
Kotlin/Native is therefore unusable for anything but `::`.

**Suggested fix** (not tested against Ktor's test suite). Copy the address into the struct in both actuals:

```kotlin
cValue<sockaddr_in6> {
    sin6_family = family.convert()
    sin6_flowinfo = flowInfo
    sin6_port = hostToNetworkOrder(port.toUShort())
    sin6_scope_id = scopeId
    rawAddress.place(sin6_addr.ptr)
    block(ptr.reinterpret(), sizeOf<sockaddr_in6>().convert())
}
```

with regression tests on every native target: a TCP and a UDP socket bound to `::1` report `::1` as `localAddress`; a TCP
listener on `::1` refuses an IPv4 connect to its port; a connect to `[::1]:<port>` reaches a listener there (this one fails
on Windows today); a connect to an IPv6 address other than the listener's (`::ffff:127.0.0.2`) does not reach it.

---

## Workaround in Kuicksilver

- `kuicksilver-ktor-network`: `connectTcp` and `bindTcp` (`@InternalKuicksilverApi`, `TcpSockets.kt`). On the JVM and
  Android they are ktor-network's `aSocket(...).tcp()`; on Kotlin/Native they are Kuicksilver's own TCP sockets on
  ktor-network's public selector API (`TcpSockets.native.kt`, adapted from Ktor's internal native socket classes), which
  pass the `sockaddr` that `getaddrinfo` returned to `bind`/`connect` unchanged. An IPv4-mapped literal is connected
  over IPv4, as on the JVM.
- Both engines use them: the server's TCP connectors (`TcpListener`) and the client's HTTP/1.1 connections, including a
  connection to an HTTP proxy (`H1Pool`).
- The portable Kotlin/Native UDP socket (`KtorDatagramIo`, used only with `IoPreference.Portable` or when the accelerated
  `ksl` socket is refused) still uses ktor-network and fails closed: it refuses to bind a specific IPv6 address and to send
  to an IPv6 address. The accelerated socket carries the full address on every platform.
- Tests: `TcpSocketsTest`, `TcpSocketsNativeTest`, `ServerH1Test.negative_ipv6ConnectorListensOnItsAddressOnly`,
  `ClientH1Test.negative_h1ToIpv6LiteralReachesThatAddressOnly`, `ClientH1Test.plainHttpToIpv6Literal`,
  `ClientH3Test.h1ToIpv6Loopback`, `KtorDatagramIoTest.negative_portableRefuses*`.

When a Ktor release fixes `nativeAddress`, the native `connectTcp`/`bindTcp` can go back to `aSocket(...).tcp()` (the
tests above stay) and the `KtorDatagramIo` guards can be removed.
