// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client.h2

import io.kuicksilver.http2.runtime.H2ClientConnection
import io.kuicksilver.ktor.client.evictEldest
import io.kuicksilver.ktor.client.h1.PoolLimits
import io.kuicksilver.ktor.client.h1.PooledConnection
import io.kuicksilver.ktor.client.h1.SpinLock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.io.IOException

/**
 * One HTTP/2 connection in the TCP pool: it holds one slot of its route in the HTTP/1.1 [io.kuicksilver.ktor.client.h1.ConnectionPool]
 * (`maxConnectionsPerRoute` and `maxConnectionsCount` count TCP connections, whatever they carry) from adoption until it
 * closes, and is never put on the idle list: [H2Pool] hands out its streams instead.
 */
internal class H2Conn(
    val client: H2ClientConnection,
    route: String,
    createdAt: Long,
) : PooledConnection(route, createdAt) {
    /** REFUSED_STREAM answers so far: the second retires the connection (OkHttp's `RealConnection.trackFailure`). */
    @kotlin.concurrent.Volatile var refusedStreams: Int = 0

    override val isOpen: Boolean get() = client.isUsable

    override fun closeTransport() {
        client.abort(IOException("the HTTP/2 connection was closed by the client"))
    }
}

/**
 * The HTTP/2 connections of the engine by route (the HTTP/1.1 route key: scheme, host, port and proxy). One connection per
 * route while it has a free stream under the server's SETTINGS_MAX_CONCURRENT_STREAMS; a full one makes room for a second,
 * within `maxConnectionsPerRoute` (the TCP pool's slots). Requests that wait for a stream or a slot watch their route's
 * [signal], which every change bumps: a released stream, new SETTINGS, a GOAWAY, a connection that came or went. Routes
 * without connections and watchers are dropped at once, so the map is bounded by the live connections and the waiters.
 * No connection coalescing across origins (RFC 9113 section 9.1.1; ADR-0017).
 */
internal class H2Pool(
    private val limits: PoolLimits,
    private val clock: () -> Long,
) {
    private class Route {
        val conns = ArrayList<H2Conn>()
        val signal = MutableStateFlow(0L)
        var watchers = 0

        /** A request that may use HTTP/2 is connecting to this route: the others wait for it (RFC 9113 section 9.1). */
        var dialing = false
    }

    private val lock = SpinLock()
    private val routes = HashMap<String, Route>()

    /** Routes whose last TLS connection negotiated HTTP/1.1 (no wait for a connect in flight there); at most [MAX_KNOWN]. */
    private val speaksH1 = LinkedHashMap<String, Unit>()

    /**
     * Whether a request that may use HTTP/2 may connect to [route] now. RFC 9113 section 9.1: clients SHOULD NOT open more
     * than one HTTP/2 connection to an origin; ALPN tells only after the handshake, so while one such connect is in flight
     * the others wait for its outcome on the route's signal (as Go's `dialCall` dedups dials per address) and then use its
     * connection, or connect in parallel when it turned out HTTP/1.1. A route known to speak HTTP/1.1 never waits. True
     * means the caller is now the route's dialer and must call [endDial].
     */
    fun tryStartDial(route: String): Boolean =
        lock.withLock {
            if (route in speaksH1) return@withLock true
            val r = routes.getOrPut(route) { Route() }
            if (r.dialing) {
                false
            } else {
                r.dialing = true
                true
            }
        }

    /** The connect of [tryStartDial] ended: [h2] true or false when it negotiated a protocol, null when it failed. */
    fun endDial(
        route: String,
        h2: Boolean?,
    ) {
        lock.withLock {
            when (h2) {
                true -> {
                    speaksH1.remove(route)
                }

                false -> {
                    speaksH1.remove(route)
                    speaksH1[route] = Unit
                    speaksH1.evictEldest(MAX_KNOWN)
                }

                null -> {}
            }
            routes[route]?.let {
                it.dialing = false
                prune(route, it)
            }
        }
        bump(route)
    }

    /** A stream on a usable connection of [route], reserved; null when none has one free. */
    fun reserve(route: String): H2Conn? {
        val now = clock()
        val list = lock.withLock { routes[route]?.conns?.toList() } ?: return null
        for (c in list) {
            if (pastLifetime(c, now)) continue
            if (c.client.tryReserve()) return c
        }
        return null
    }

    /** Whether [route] has an HTTP/2 connection (usable or not). */
    fun has(route: String): Boolean = lock.withLock { routes[route]?.conns?.isNotEmpty() == true }

    /** Adds [c], adopted by the TCP pool already, to its route. */
    fun register(c: H2Conn) {
        lock.withLock { routes.getOrPut(c.route) { Route() }.conns += c }
        bump(c.route)
    }

    /** Drops [c] from its route (closed, or retired: its streams finish but it takes no new ones). */
    fun remove(c: H2Conn) {
        lock.withLock {
            val r = routes[c.route] ?: return@withLock
            r.conns.remove(c)
            prune(c.route, r)
        }
        bump(c.route)
    }

    /** Something changed on [route]: its watchers look again. */
    fun bump(route: String) {
        lock.withLock { routes[route] }?.signal?.update { it + 1 }
    }

    /** The change signal of [route], held until [unwatch]. */
    fun watch(route: String): StateFlow<Long> =
        lock.withLock {
            val r = routes.getOrPut(route) { Route() }
            r.watchers++
            r.signal
        }

    fun unwatch(route: String) {
        lock.withLock {
            val r = routes[route] ?: return@withLock
            r.watchers--
            prune(route, r)
        }
    }

    private fun prune(
        route: String,
        r: Route,
    ) {
        if (r.conns.isEmpty() && r.watchers <= 0 && !r.dialing) routes.remove(route)
    }

    private fun pastLifetime(
        c: H2Conn,
        now: Long,
    ): Boolean = limits.maxLifetimeMillis != Long.MAX_VALUE && now - c.createdAt >= limits.maxLifetimeMillis

    /**
     * Retires connections without streams past `idleTimeout` (GOAWAY, then closed) and connections past
     * `maxConnectionLifetime` (no new streams; closed when their streams are done); returns the milliseconds until the
     * next of these, null when there is none to wait for.
     */
    fun evictExpired(): Long? {
        val now = clock()
        var next: Long? = null
        val retire = ArrayList<H2Conn>()

        fun at(d: Long) {
            next = next?.let { minOf(it, d) } ?: d
        }
        val all = lock.withLock { routes.values.flatMap { it.conns } }
        for (c in all) {
            if (pastLifetime(c, now)) {
                retire += c
                continue
            }
            if (limits.maxLifetimeMillis != Long.MAX_VALUE) at(c.createdAt + limits.maxLifetimeMillis - now)
            if (c.client.reservedStreams == 0) {
                val idleFor = c.client.nowMillis() - c.client.idleSinceMillis
                if (idleFor >= limits.idleTimeoutMillis) retire += c else at(limits.idleTimeoutMillis - idleFor)
            }
        }
        for (c in retire) {
            remove(c)
            c.client.shutdown() // GOAWAY (NO_ERROR); the transport closes when the last stream is done
        }
        return next
    }

    /** Closes every connection (the engine is closing; its calls are done). */
    fun closeAll() {
        val all =
            lock.withLock {
                val l = routes.values.flatMap { it.conns }
                routes.values.forEach { it.conns.clear() }
                routes.values.removeAll { it.watchers <= 0 }
                l
            }
        for (c in all) {
            c.client.shutdown()
            c.close()
        }
    }

    /** Connections (the resource probe). */
    val connectionCount: Int get() = lock.withLock { routes.values.sumOf { it.conns.size } }

    /** Streams in use on them (the resource probe). */
    val streamCount: Int get() = lock.withLock { routes.values.flatMap { it.conns } }.sumOf { it.client.reservedStreams }

    /** Routes tracked (tests: bounded by the connections and the waiters). */
    val routeCount: Int get() = lock.withLock { routes.size }

    private companion object {
        const val MAX_KNOWN = 1000
    }
}

/**
 * Routes whose server answered HTTP_1_1_REQUIRED (RFC 9113 section 7): their new connections offer only `http/1.1` for
 * 5 minutes, doubling at each new refusal up to 2 days (the backoff of `BrokenAltSvc`), at most 1000 routes (the least
 * recently marked go first).
 */
internal class H2RefusedRoutes(
    private val clock: () -> Long,
) {
    private class Mark(
        val until: Long,
        val level: Int,
    )

    private val lock = SpinLock()
    private val marks = LinkedHashMap<String, Mark>()

    fun mark(route: String) {
        lock.withLock {
            val level = marks[route]?.let { it.level + 1 } ?: 0
            marks.remove(route)
            marks[route] = Mark(clock() + (BASE_MILLIS shl minOf(level, 20)).coerceAtMost(MAX_MILLIS), level)
            marks.evictEldest(MAX_ROUTES)
        }
    }

    fun isRefused(route: String): Boolean = lock.withLock { (marks[route]?.until ?: return@withLock false) > clock() }

    val size: Int get() = lock.withLock { marks.size }

    private companion object {
        const val BASE_MILLIS = 5 * 60 * 1000L
        const val MAX_MILLIS = 2 * 86_400 * 1000L
        const val MAX_ROUTES = 1000
    }
}
