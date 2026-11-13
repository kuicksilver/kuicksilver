// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client.pac

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import platform.darwin.inet_ntop
import platform.darwin.inet_pton
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.AF_UNSPEC
import platform.posix.INET6_ADDRSTRLEN
import platform.posix.IPPROTO_UDP
import platform.posix.SOCK_DGRAM
import platform.posix.SOCK_STREAM
import platform.posix.addrinfo
import platform.posix.close
import platform.posix.connect
import platform.posix.freeaddrinfo
import platform.posix.getaddrinfo
import platform.posix.getsockname
import platform.posix.sockaddr
import platform.posix.sockaddr_in
import platform.posix.sockaddr_in6
import platform.posix.socket
import platform.posix.socklen_tVar
import kotlin.concurrent.AtomicReference

/**
 * What a PAC script may learn of the host, through the four native functions of [PacContext]: name resolution and the
 * host's own addresses. [current] is the system's; tests replace it.
 */
internal interface PacHost {
    /** The addresses of [name] as text, IPv4 only or every family; empty when it does not resolve. */
    fun resolve(
        name: String,
        ipv4Only: Boolean,
    ): List<String>

    /** This host's addresses as text, the one of the default route first. */
    fun myAddresses(ipv4Only: Boolean): List<String>

    companion object {
        private val override = AtomicReference<PacHost?>(null)

        val current: PacHost get() = override.value ?: SystemPacHost

        /** Tests: [host] answers the script's native calls until it is set back to null. */
        fun setForTest(host: PacHost?) {
            override.value = host
        }
    }
}

/** `getaddrinfo` for names; for this host's address the source address of a UDP socket connected to a public address. */
internal object SystemPacHost : PacHost {
    override fun resolve(
        name: String,
        ipv4Only: Boolean,
    ): List<String> =
        memScoped {
            val hints = alloc<addrinfo>()
            hints.ai_family = if (ipv4Only) AF_INET else AF_UNSPEC
            hints.ai_socktype = SOCK_STREAM
            val res = alloc<kotlinx.cinterop.CPointerVar<addrinfo>>()
            if (getaddrinfo(name, null, hints.ptr, res.ptr) != 0) return emptyList()
            val out = LinkedHashSet<String>()
            try {
                var p = res.value
                while (p != null) {
                    p.pointed.ai_addr?.let { a -> text(a)?.let { out += it } }
                    p = p.pointed.ai_next
                }
            } finally {
                freeaddrinfo(res.value)
            }
            out.toList()
        }

    override fun myAddresses(ipv4Only: Boolean): List<String> {
        // as browsers do: the source address the routing table picks for a public destination; no packet is sent
        val out = ArrayList<String>()
        sourceAddress(AF_INET, "198.51.100.1")?.let { out += it }
        if (!ipv4Only) sourceAddress(AF_INET6, "2001:db8::1")?.let { out += it }
        return out
    }

    private fun sourceAddress(
        family: Int,
        destination: String,
    ): String? =
        memScoped {
            val fd = socket(family, SOCK_DGRAM, IPPROTO_UDP)
            if (fd < 0) return null
            try {
                if (family == AF_INET) {
                    val to = alloc<sockaddr_in>()
                    to.sin_family = AF_INET.convert()
                    to.sin_port = 0x3500u // 53 in network order
                    if (inet_pton(AF_INET, destination, to.sin_addr.ptr) != 1) return null
                    if (connect(fd, to.ptr.reinterpret(), sizeOf<sockaddr_in>().convert()) != 0) return null
                    val local = alloc<sockaddr_in>()
                    val len = alloc<socklen_tVar>().also { it.value = sizeOf<sockaddr_in>().convert() }
                    if (getsockname(fd, local.ptr.reinterpret(), len.ptr) != 0) return null
                    text(local.ptr.reinterpret())
                } else {
                    val to = alloc<sockaddr_in6>()
                    to.sin6_family = AF_INET6.convert()
                    to.sin6_port = 0x3500u
                    if (inet_pton(AF_INET6, destination, to.sin6_addr.ptr) != 1) return null
                    if (connect(fd, to.ptr.reinterpret(), sizeOf<sockaddr_in6>().convert()) != 0) return null
                    val local = alloc<sockaddr_in6>()
                    val len = alloc<socklen_tVar>().also { it.value = sizeOf<sockaddr_in6>().convert() }
                    if (getsockname(fd, local.ptr.reinterpret(), len.ptr) != 0) return null
                    text(local.ptr.reinterpret())
                }
            } finally {
                close(fd)
            }
        }

    private fun text(a: CPointer<sockaddr>): String? =
        memScoped {
            val buf = allocArray<ByteVar>(INET6_ADDRSTRLEN)
            when (a.pointed.sa_family.toInt()) {
                AF_INET -> {
                    inet_ntop(
                        AF_INET,
                        a
                            .reinterpret<sockaddr_in>()
                            .pointed.sin_addr.ptr,
                        buf,
                        INET6_ADDRSTRLEN.convert(),
                    )
                }

                AF_INET6 -> {
                    inet_ntop(
                        AF_INET6,
                        a
                            .reinterpret<sockaddr_in6>()
                            .pointed.sin6_addr.ptr,
                        buf,
                        INET6_ADDRSTRLEN.convert(),
                    )
                }

                else -> {
                    return null
                }
            } ?: return null
            buf.toKString().takeUnless { it == "0.0.0.0" || it == "::" }
        }
}

/**
 * The most distinct names (per function family: `dnsResolve` and `isResolvable`, or `dnsResolveEx` and `isResolvableEx`)
 * one run of a script may resolve, Chromium's `kMaxUniqueResolveDnsPerExec`: later new names resolve to nothing.
 */
internal const val PAC_MAX_DNS_LOOKUPS: Int = 20

/**
 * Name resolution for a script's `dnsResolve` and `dnsResolveEx`: during a run of [PacRunner] each lookup runs on one of
 * [PacDns.THREADS] threads of [Dispatchers.IO] and is waited for at most what remains of the run's DNS budget ([PacRun.remaining]); a
 * lookup that does not answer in time resolves to nothing (its thread ends with `getaddrinfo`, its answer dropped), so a
 * slow resolver cannot make a script overrun its limit. Answers are kept for the rest of the run; a run resolves at most
 * [PAC_MAX_DNS_LOOKUPS] distinct names (a name and its family), later new ones resolve to nothing without a lookup.
 * Outside a run (tests of the utility functions) the lookup is made directly.
 */
@OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
internal object PacDns {
    /**
     * The threads lookups run on: at most [THREADS] of `Dispatchers.IO`, so lookups stuck in `getaddrinfo` (given up by
     * their runs, their threads still blocked) hold at most that many; later lookups queue and are given up in time.
     */
    const val THREADS: Int = 4
    private val lookups = Dispatchers.IO.limitedParallelism(THREADS)

    fun resolve(
        name: String,
        ipv4Only: Boolean,
    ): List<String> {
        if (PacRun.deadline == 0L) return PacHost.current.resolve(name, ipv4Only)
        PacRun.answers[name to ipv4Only]?.let { return it }
        if (PacRun.answers.size >= PAC_MAX_DNS_LOOKUPS) return emptyList() // as Chromium: the run goes on, the name fails
        val remaining = PacRun.remaining()
        if (remaining <= 0) return emptyList()
        val host = PacHost.current
        val lookup = GlobalScope.async(lookups) { host.resolve(name, ipv4Only) }
        val answer =
            runBlocking { withTimeoutOrNull(remaining) { lookup.await() } }
                ?: emptyList<String>().also { lookup.cancel() }
        PacRun.answers[name to ipv4Only] = answer
        return answer
    }
}
