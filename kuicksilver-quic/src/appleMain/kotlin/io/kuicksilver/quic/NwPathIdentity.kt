// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import platform.Network.nw_endpoint_copy_address_string
import platform.Network.nw_path_enumerate_gateways
import platform.Network.nw_path_monitor_cancel
import platform.Network.nw_path_monitor_create
import platform.Network.nw_path_monitor_set_queue
import platform.Network.nw_path_monitor_set_update_handler
import platform.Network.nw_path_monitor_start
import platform.Network.nw_path_t
import platform.darwin.dispatch_queue_create
import platform.darwin.freeifaddrs
import platform.darwin.getifaddrs
import platform.darwin.ifaddrs
import platform.darwin.inet_ntop
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.INET6_ADDRSTRLEN
import platform.posix.free
import platform.posix.sockaddr_in
import platform.posix.sockaddr_in6

/**
 * The identity of the system's default path as a network, for telling networks apart (iOS, macOS): the interface (as
 * [NwPathKey]), the path's gateways (`nw_path_enumerate_gateways`) and the interface's own addresses (IPv4 with its mask,
 * the /64 prefixes of global IPv6 addresses), so a move from one Wi-Fi network to another on the same interface is a
 * change, which [NwPathKey] alone does not see. Null while the path is not satisfied. When a satisfied path tells neither
 * gateways nor addresses, every update of it is a value of its own, so each counts as a change (the safe side for caches
 * that must be flushed on a network change). The values are opaque text meant for comparison in memory only: they carry
 * local addresses and must be neither stored nor logged. One path monitor per process, shared by the collectors.
 */
@InternalKuicksilverApi
public fun nwPathIdentities(): Flow<String?> = sharedPathIdentities[Unit]

private val sharedPathIdentities = SharedPerKey<Unit, String?> { monitorPathIdentities() }

private fun monitorPathIdentities(): Flow<String?> =
    callbackFlow {
        val monitor = nw_path_monitor_create() ?: throw IllegalStateException("nw_path_monitor_create failed")
        var unknown = 0L // updates run on the monitor's serial queue
        nw_path_monitor_set_update_handler(monitor) { path ->
            val key = pathKeyOf(path)
            val id =
                if (key ==
                    null
                ) {
                    null
                } else {
                    pathIdentity(key, gatewaysOf(path), interfaceAddresses(key.interfaceName)) ?: "?${++unknown}"
                }
            trySend(id)
        }
        nw_path_monitor_set_queue(monitor, dispatch_queue_create("io.kuicksilver.nw-path-identity", null))
        nw_path_monitor_start(monitor)
        awaitClose { nw_path_monitor_cancel(monitor) }
    }.buffer(Channel.UNLIMITED).distinctUntilChanged()

/**
 * The identity of a satisfied path on [key]'s interface with [gateways] and [addresses] (any order), or null when neither
 * says anything about the network behind the interface.
 */
internal fun pathIdentity(
    key: NwPathKey,
    gateways: List<String>,
    addresses: List<String>,
): String? {
    if (gateways.isEmpty() && addresses.isEmpty()) return null
    return "${key.interfaceIndex}|${key.interfaceType}|${gateways.sorted().joinToString(",")}|${addresses.sorted().joinToString(",")}"
}

/** The gateway addresses of [path], as text. */
private fun gatewaysOf(path: nw_path_t): List<String> {
    val out = ArrayList<String>()
    nw_path_enumerate_gateways(path) { endpoint ->
        val s: CPointer<ByteVar>? = nw_endpoint_copy_address_string(endpoint)
        if (s != null) {
            out += s.toKString()
            free(s)
        }
        true
    }
    return out
}

/** The IPv4 addresses with their masks, and the /64 prefixes of the global IPv6 addresses, of interface [name]. */
private fun interfaceAddresses(name: String): List<String> =
    memScoped {
        val out = ArrayList<String>()
        val list = alloc<CPointerVar<ifaddrs>>()
        if (getifaddrs(list.ptr) != 0) return@memScoped out
        try {
            var p = list.value
            val text = allocArray<ByteVar>(INET6_ADDRSTRLEN)
            while (p != null) {
                val ifa = p.pointed
                val addr = ifa.ifa_addr
                if (addr != null && ifa.ifa_name?.toKString() == name) {
                    when (addr.pointed.sa_family.toInt()) {
                        AF_INET -> {
                            val a = addr.reinterpret<sockaddr_in>().pointed
                            val m = ifa.ifa_netmask?.reinterpret<sockaddr_in>()?.pointed
                            if (inet_ntop(AF_INET, a.sin_addr.ptr, text, INET6_ADDRSTRLEN.toUInt()) != null) {
                                val ip = text.toKString()
                                val mask =
                                    m?.let {
                                        if (inet_ntop(AF_INET, it.sin_addr.ptr, text, INET6_ADDRSTRLEN.toUInt()) !=
                                            null
                                        ) {
                                            text.toKString()
                                        } else {
                                            null
                                        }
                                    }
                                out += "$ip/$mask"
                            }
                        }

                        AF_INET6 -> {
                            val b =
                                addr
                                    .reinterpret<sockaddr_in6>()
                                    .pointed.sin6_addr.ptr
                                    .reinterpret<UByteVar>()
                            val first = b[0].toInt()
                            // global unicast (2000::/3): its /64 prefix is the network's; link-local and ULA say less
                            if (first and 0xe0 ==
                                0x20
                            ) {
                                out += (0 until 8).joinToString("") { b[it].toString(16).padStart(2, '0') } + "::/64"
                            }
                        }
                    }
                }
                p = ifa.ifa_next
            }
        } finally {
            freeifaddrs(list.value)
        }
        out.distinct()
    }
