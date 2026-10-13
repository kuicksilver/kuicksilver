<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Draft: Ktor issue "Kotlin/Native sockets bind and connect every IPv6 address as `::`"

Status: **draft, not filed**. Filing it is the owner's decision. Target: YouTrack, project KTOR, subsystem `Network`
(ktor-network). Checked on 2026-10-13: the bug is present in the 3.6.0 tag and on `main`; no open or closed KTOR issue
describes it (searches for `IPv6`, `sockaddr_in6`, `NativeIPv6SocketAddress`). KTOR-9532 (iOS, UDP "Operation not
permitted" on an IPv6-only carrier) may have this root cause; that is not verified.

Kuicksilver works around it in its own code (see "Workaround in Kuicksilver" at the end); the text below is what would go
upstream.

---

**Title:** Native: IPv6 socket addresses are bound and connected as `::` (address bytes never copied into `sockaddr_in6`)

**Affected:** ktor-network 3.6.0 (and `main` as of 2026-10-13), every Kotlin/Native target: Linux, Apple (macOS, iOS,
tvOS, watchOS), Windows (mingwX64), Android Native. JVM and JS are not affected.

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

**Reproducer** (Kotlin/Native, any target with an IPv6 loopback):

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

Observed: macOS 26 (macosArm64): a listener bound to `::1` reports `::` and accepts `127.0.0.1:<port>`; a request to
`[::ffff:127.0.0.1]:<port>` (nothing listens there) is answered by the `::1` listener. Windows 11 (mingwX64): the connect
to `[::1]:<port>` fails with `POSIX error 10049`.

**Root cause.** `ktor-network/nix/src/io/ktor/network/util/NativeSocketAddressNix.kt`, lines 63-72 (tag 3.6.0), and the
same code in `ktor-network/windows/src/io/ktor/network/util/NativeSocketAddressWindows.kt`, lines 66-75:

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
(`ktor-network/posix/src/io/ktor/network/sockets/ConnectUtilsNative.kt:70`, `TCPSocketNative.kt:28`), `udpBind` and
`udpConnect` (`UDPSocketBuilderNative.kt:29, 33, 62`) and datagram sends (`DatagramSendChannel.kt:111`).

**Suggested fix.** Copy the address into the struct in both actuals:

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
