// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.withContext
import kotlinx.io.IOException
import platform.Network.nw_interface_get_index
import platform.Network.nw_interface_get_name
import platform.Network.nw_interface_get_type
import platform.Network.nw_interface_t
import platform.Network.nw_interface_type_cellular
import platform.Network.nw_interface_type_loopback
import platform.Network.nw_interface_type_wifi
import platform.Network.nw_interface_type_wired
import platform.Network.nw_path_enumerate_interfaces
import platform.Network.nw_path_get_status
import platform.Network.nw_path_monitor_cancel
import platform.Network.nw_path_monitor_create
import platform.Network.nw_path_monitor_set_queue
import platform.Network.nw_path_monitor_set_update_handler
import platform.Network.nw_path_monitor_start
import platform.Network.nw_path_status_satisfied
import platform.Network.nw_path_t
import platform.darwin.dispatch_queue_create
import platform.posix.AF_INET6
import platform.posix.IPPROTO_IP
import platform.posix.IPPROTO_IPV6
import platform.posix.errno
import platform.posix.getsockname
import platform.posix.getsockopt
import platform.posix.setsockopt
import platform.posix.sockaddr_storage
import platform.posix.socklen_tVar
import platform.posix.strerror
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch

/** The kind of interface an [NwPathKey] names (`nw_interface_type_t`). */
@ExperimentalKuicksilverApi
public enum class NwInterfaceType {
    /** Wi-Fi. */
    Wifi,

    /** Cellular data. */
    Cellular,

    /** Ethernet (also a USB or Thunderbolt adapter). */
    Wired,

    /** The loopback interface. */
    Loopback,

    /** Anything else: a VPN tunnel (`utun`), a bridge, an unknown kind. */
    Other,
}

/**
 * The network a satisfied default path runs over, as [nwPathUpdates] reports it: the path's preferred interface, the first
 * one `nw_path_enumerate_interfaces` lists (the order of preference, as `NWPath.availableInterfaces`). Two keys are equal when [interfaceIndex] and [interfaceType] are, which makes it
 * the `N` of a [NetworkMigrator]: a change of key is a change of network, a path update that keeps the interface (a new
 * address, a DNS change) is not.
 */
@ExperimentalKuicksilverApi
public class NwPathKey(
    /** The interface index (`nw_interface_get_index`, `if_nametoindex`): what [DatagramIo.Companion.open] binds a socket to. */
    public val interfaceIndex: Int,
    /** The interface's kind. */
    public val interfaceType: NwInterfaceType,
    /** The interface's BSD name (`en0`, `pdp_ip0`), for logs; not part of equality. */
    public val interfaceName: String,
) {
    /** Equal [interfaceIndex] and [interfaceType]. */
    override fun equals(other: Any?): Boolean =
        other is NwPathKey && other.interfaceIndex == interfaceIndex && other.interfaceType == interfaceType

    /** From [interfaceIndex] and [interfaceType]. */
    override fun hashCode(): Int = interfaceIndex * 31 + interfaceType.hashCode()

    /** For logs. */
    override fun toString(): String = "NwPathKey($interfaceName#$interfaceIndex, $interfaceType)"
}

/**
 * The system's default path (`NWPathMonitor` through the Network framework's C API) as a [NetworkMigrator] source on iOS and
 * macOS: the key of the current path first, then each change, null while the path is not satisfied (no usable network).
 * Equal consecutive keys are reported once. All collectors in the process share one monitor, started with the first collector
 * on its own dispatch queue and cancelled when the last one stops; a later collector gets the latest key first.
 */
@ExperimentalKuicksilverApi
public fun nwPathUpdates(): Flow<NwPathKey?> = sharedPathUpdates[Unit]

/** One path monitor per process, however many connections follow it. */
private val sharedPathUpdates = SharedPerKey<Unit, NwPathKey?> { monitorPaths() }

/** Monitors started so far (test hook: collectors share one). */
internal val pathMonitorsStarted = AtomicInt(0)

private fun monitorPaths(): Flow<NwPathKey?> =
    callbackFlow {
        val monitor = nw_path_monitor_create() ?: throw IllegalStateException("nw_path_monitor_create failed")
        pathMonitorsStarted.incrementAndFetch()
        nw_path_monitor_set_update_handler(monitor) { path -> trySend(pathKeyOf(path)) }
        nw_path_monitor_set_queue(monitor, dispatch_queue_create("io.kuicksilver.nw-path", null))
        nw_path_monitor_start(monitor)
        awaitClose { nw_path_monitor_cancel(monitor) }
    }.buffer(Channel.UNLIMITED).distinctUntilChanged()

/** The key of a path: null unless satisfied; otherwise its preferred (first) interface. */
internal fun pathKeyOf(path: nw_path_t): NwPathKey? {
    if (path == null || nw_path_get_status(path) != nw_path_status_satisfied) return null
    var key: NwPathKey? = null
    nw_path_enumerate_interfaces(path) { iface: nw_interface_t ->
        key = interfaceKeyOf(iface)
        false // the first interface is the preferred one
    }
    return key
}

private fun interfaceKeyOf(iface: nw_interface_t): NwPathKey? {
    if (iface == null) return null
    val type =
        when (nw_interface_get_type(iface)) {
            nw_interface_type_wifi -> NwInterfaceType.Wifi
            nw_interface_type_cellular -> NwInterfaceType.Cellular
            nw_interface_type_wired -> NwInterfaceType.Wired
            nw_interface_type_loopback -> NwInterfaceType.Loopback
            else -> NwInterfaceType.Other
        }
    return NwPathKey(nw_interface_get_index(iface).toInt(), type, nw_interface_get_name(iface)?.toKString().orEmpty())
}

/**
 * Binds [local] to interface [interfaceIndex] (iOS, macOS; an [NwPathKey.interfaceIndex] or `if_nametoindex`): every datagram
 * of the socket leaves through that interface whatever the default route is (`IP_BOUND_IF`; `IPV6_BOUND_IF` on an IPv6
 * socket, which a wildcard address opens dual-stack), so a connection can move to a network before the system prefers it. The accelerated transport when [prefer] asks
 * for it; the portable socket cannot be bound to an interface, so when the accelerated one is refused (or [prefer] is
 * [IoPreference.Portable]) the socket is unbound and follows the default route. Throws [IOException] when the system refuses
 * the binding (an index that names no interface); the socket is closed then.
 */
@ExperimentalKuicksilverApi
public suspend fun DatagramIo.Companion.open(
    local: InetSocketAddress,
    interfaceIndex: Int,
    prefer: IoPreference = IoPreference.Accelerated,
): DatagramIo =
    withContext(Dispatchers.IO) {
        // the socket's own family: a wildcard address opens a dual-stack IPv6 socket, where only IPV6_BOUND_IF applies (to both families)
        val accelerated =
            if (prefer ==
                IoPreference.Accelerated
            ) {
                KslDatagramIo.open(local) { fd -> bindToInterface(fd, interfaceIndex, isIpv6Socket(fd)) }
            } else {
                null
            }
        accelerated ?: openPortableDatagramIo(local)
    }

/** True for an AF_INET6 socket (`getsockname`). */
internal fun isIpv6Socket(fd: Int): Boolean =
    memScoped {
        val ss = alloc<sockaddr_storage>()
        val len = alloc<socklen_tVar>()
        len.value = sizeOf<sockaddr_storage>().toUInt()
        check(getsockname(fd, ss.ptr.reinterpret(), len.ptr) == 0) { "getsockname: errno $errno" }
        ss.ss_family.toInt() == AF_INET6
    }

/** `IP_BOUND_IF` / `IPV6_BOUND_IF` (Darwin `netinet/in.h`, `netinet6/in6.h`). */
private const val IP_BOUND_IF = 25
private const val IPV6_BOUND_IF = 125

private fun bindToInterface(
    fd: Int,
    index: Int,
    v6: Boolean,
) = memScoped {
    val v = alloc<IntVar>()
    v.value = index
    val rc =
        if (v6) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, v.ptr, sizeOf<IntVar>().toUInt())
        } else {
            setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, v.ptr, sizeOf<IntVar>().toUInt())
        }
    if (rc != 0) {
        val e = errno
        throw IOException("binding the socket to interface $index failed: ${strerror(e)?.toKString()} ($e)")
    }
}

/** The interface a socket is bound to (0: none); tests read back what [bindToInterface] set. */
internal fun boundInterfaceOf(
    fd: Int,
    v6: Boolean,
): Int =
    memScoped {
        val v = alloc<IntVar>()
        val len = alloc<socklen_tVar>()
        len.value = sizeOf<IntVar>().toUInt()
        val rc =
            if (v6) {
                getsockopt(
                    fd,
                    IPPROTO_IPV6,
                    IPV6_BOUND_IF,
                    v.ptr,
                    len.ptr,
                )
            } else {
                getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, v.ptr, len.ptr)
            }
        check(rc == 0) { "getsockopt: errno $errno" }
        v.value
    }

/**
 * Keeps this client connection on the system's default network (iOS, macOS): a started [NetworkMigrator] over [nwPathUpdates]
 * that opens each new socket with [DatagramIo.Companion.open] bound to the new path's interface (at [local]: the wildcard
 * address of the server's family by default, any port). The path when this is called is taken as the one the connection is
 * on (an unbound socket follows the default route). It also replaces a socket iOS reclaimed while the app was suspended
 * ([PathEvent.SocketLost]). Collect [NetworkMigrator.events] right after this call to see every event; [NetworkMigrator.close]
 * stops following.
 */
@ExperimentalKuicksilverApi
public fun QuicConnection.followDefaultNetwork(
    scope: CoroutineScope,
    local: InetSocketAddress? = null,
    prefer: IoPreference = IoPreference.Accelerated,
): NetworkMigrator<NwPathKey> = followNetworks(nwPathUpdates(), scope, local, prefer)

/** [followDefaultNetwork] over any source of keys (tests feed their own). */
internal fun QuicConnection.followNetworks(
    keys: Flow<NwPathKey?>,
    scope: CoroutineScope,
    local: InetSocketAddress?,
    prefer: IoPreference,
): NetworkMigrator<NwPathKey> {
    val bindTo = local ?: wildcardLocal()
    return NetworkMigrator(this, keys, { k -> DatagramIo.open(bindTo, k.interfaceIndex, prefer) }, scope).also { it.start() }
}
