// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.time.Duration

// The JDK's sockets carry the full address: ktor-network connects and binds as it is, but writes through KslNioSocket
// (ktor 3.6.0's writer spun at 100 % CPU while a peer's window was closed, KTOR-9959, fixed in 3.6.1; KslNioSocket also counts
// the bytes sent and bounds the close).
@InternalKuicksilverApi
public actual suspend fun connectTcp(
    selector: SelectorManager,
    remote: InetSocketAddress,
    receiveBufferSize: Int,
): Socket {
    require(receiveBufferSize >= 0) { "receiveBufferSize $receiveBufferSize is negative" }
    val socket = aSocket(selector).tcp().connect(remote) { if (receiveBufferSize > 0) this.receiveBufferSize = receiveBufferSize }
    return KslNioSocket(socket, selector, CLIENT_CLOSE_TIMEOUT)
}

@InternalKuicksilverApi
public actual suspend fun connectTcpAddress(
    selector: SelectorManager,
    address: TcpAddress,
): Socket =
    // a literal: java.net.InetSocketAddress parses it without a lookup
    KslNioSocket(aSocket(selector).tcp().connect(InetSocketAddress(address.hostText, address.port)), selector, CLIENT_CLOSE_TIMEOUT)

internal actual fun platformResolveTcp(
    name: String,
    port: Int,
    numericHost: Boolean,
): List<TcpAddress> {
    // getAllByName parses a host that starts with a hex digit or ':' and contains ':' as an IPv6 literal and fails on an
    // invalid one without a lookup; any other host with a ':' would be looked up, so it is refused here
    if (numericHost && !(name.isNotEmpty() && (name[0] == ':' || Character.digit(name[0], 16) >= 0) && ':' in name)) {
        throw java.net.UnknownHostException("$name: not an IP address literal")
    }
    return java.net.InetAddress.getAllByName(name).map { a ->
        TcpAddress(a.address, port, (a as? java.net.Inet6Address)?.scopeId ?: 0)
    }
}

internal actual fun platformResolveFamily(
    name: String,
    ipv6: Boolean,
): List<TcpAddress> {
    // the JDK opens IPv4 sockets only: an IPv6 address could not be connected to
    if (ipv6 && System.getProperty("java.net.preferIPv4Stack").toBoolean()) return emptyList()
    if (!jdkResolverReplaced) kslResolveFamily(name, ipv6)?.let { return it }
    // the application's resolver (or no native library): one lookup answers both families, filtered here
    return platformResolveTcp(name, 0, numericHost = false).filter { it.isIpv6 == ipv6 }
}

/**
 * What `InetAddress` would keep: `networkaddress.cache.ttl` and `networkaddress.cache.negative.ttl` (security properties,
 * or the `sun.net.inetaddr` system properties), 30 s and 10 s by default as the JDK has them; Android keeps 2 s.
 */
internal actual fun platformLookupCacheTtl(): LookupTtl {
    fun read(
        security: String,
        system: String,
        default: Long,
    ): Long =
        try {
            java.security.Security
                .getProperty(security)
                ?.trim()
                ?.toLongOrNull() ?: System.getProperty(system)?.trim()?.toLongOrNull() ?: default
        } catch (_: SecurityException) {
            default
        }
    val android = System.getProperty("java.vm.name").orEmpty().contains("Dalvik", ignoreCase = true)
    return if (android) {
        LookupTtl(2, 2)
    } else {
        LookupTtl(
            read("networkaddress.cache.ttl", "sun.net.inetaddr.ttl", 30),
            read("networkaddress.cache.negative.ttl", "sun.net.inetaddr.negative.ttl", 10),
        )
    }
}

/**
 * Whether the application replaced the JDK's resolver: a hosts file of its own (`jdk.net.hosts.file`) or an
 * `InetAddressResolverProvider` (JDK 18+). Name lookups then go through `InetAddress`, as the application expects.
 */
private val jdkResolverReplaced: Boolean by lazy {
    System.getProperty("jdk.net.hosts.file") != null ||
        try {
            val spi = Class.forName("java.net.spi.InetAddressResolverProvider")
            java.util.ServiceLoader
                .load(spi, ClassLoader.getSystemClassLoader())
                .iterator()
                .hasNext()
        } catch (_: Throwable) {
            false // no such SPI (before JDK 18, Android), or a provider that cannot be loaded: the JDK ignores it too
        }
}

@InternalKuicksilverApi
public actual suspend fun bindTcp(
    selector: SelectorManager,
    host: String,
    port: Int,
): ServerSocket = KslNioServerSocket(aSocket(selector).tcp().bind(host, port), selector)

internal actual fun Socket.rawBytesSent(): Long? = (this as? KslNioSocket)?.bytesWritten?.get()

internal actual fun Socket.setRawCloseTimeout(timeout: Duration?) {
    if (this is KslNioSocket) closeTimeout = timeout
}

internal actual fun Socket.abortTcp() {
    if (this is KslNioSocket) {
        abort()
    } else {
        close()
        socketContext.cancel()
    }
}

internal actual fun Socket.holdReadEndForTest(hook: (suspend () -> Unit)?) {
    if (this is KslNioSocket) atReadEndForTest = hook
}

internal actual fun Socket.tcpReadDelivery(): ReadDelivery? = (this as? KslNioSocket)?.readDelivery

internal actual fun Socket.sendFailuresForTest(): SendFailures? = (this as? KslNioSocket)?.sendFailures

internal actual fun platformSourceAddress(destination: TcpAddress): TcpAddress? =
    java.net.DatagramSocket(null as java.net.SocketAddress?).use { s ->
        // connect only selects the route and the source address (no packet); without one it throws, or stays unconnected
        s.connect(java.net.InetSocketAddress(java.net.InetAddress.getByAddress(destination.bytes), destination.port))
        val local = s.localAddress
        if (!s.isConnected || local == null || local.isAnyLocalAddress) {
            null
        } else {
            TcpAddress(local.address, 0, (local as? java.net.Inet6Address)?.scopeId ?: 0) // a link-local source keeps its zone
        }
    }
