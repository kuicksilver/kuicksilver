// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.client.h1

import io.ktor.client.engine.ClientEngineClosedException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/** A lock for short sections that never suspend: the pool is also entered from completion handlers, which cannot suspend. */
internal class SpinLock {
    @PublishedApi internal val held: AtomicInt = AtomicInt(0)

    inline fun <T> withLock(block: () -> T): T {
        while (!held.compareAndSet(0, 1)) {
            // the holder runs a few map operations and leaves; nothing in a section suspends or blocks
        }
        try {
            return block()
        } finally {
            held.store(0)
        }
    }
}

/**
 * A connection a [ConnectionPool] accounts for: it holds one slot of its route and of the pool from [ConnectionPool.adopt]
 * until it is closed or the pool drops it, and the slot comes back exactly once whoever gets there first.
 */
internal abstract class PooledConnection(
    /** The route (origin and proxy) it serves. */
    val route: String,
    /** When it was opened, on the pool's clock. */
    val createdAt: Long,
) {
    private val closedFlag = AtomicInt(0)
    private val slotFlag = AtomicInt(0)

    /** Set by [ConnectionPool.adopt]; null for a connection no pool accounts for. */
    internal var pool: ConnectionPool<*>? = null

    /** When it went idle, on the pool's clock; guarded by the pool's lock. */
    internal var idleSince: Long = 0

    /** Whether [close] ran. */
    val closed: Boolean get() = closedFlag.load() != 0

    /** Whether it can carry another exchange: not closed and the peer has not closed it (stale-socket detection). */
    abstract val isOpen: Boolean

    /** Closes the transport; called once. */
    protected abstract fun closeTransport()

    /** Closes the connection and gives its slot back; idempotent and safe from any thread. */
    fun close() {
        if (closedFlag.compareAndSet(0, 1)) closeTransport()
        pool?.slotReturned(this)
    }

    /** True for the one caller that gives the slot back. */
    internal fun claimSlot(): Boolean = slotFlag.compareAndSet(0, 1)
}

/**
 * Limits of a [ConnectionPool].
 *
 * @property maxTotal connections open at once, idle ones included (CIO's `maxConnectionsCount`).
 * @property maxPerRoute connections open at once to one route (CIO's `endpoint.maxConnectionsPerRoute`).
 * @property maxIdlePerRoute idle connections kept per route.
 * @property idleTimeoutMillis how long an idle connection is kept; [Long.MAX_VALUE] for ever.
 * @property maxLifetimeMillis age after which a connection is not reused; [Long.MAX_VALUE] for none.
 */
internal class PoolLimits(
    val maxTotal: Int,
    val maxPerRoute: Int,
    val maxIdlePerRoute: Int,
    val idleTimeoutMillis: Long,
    val maxLifetimeMillis: Long,
) {
    init {
        require(maxTotal > 0) { "maxConnectionsCount must be positive, was $maxTotal" }
        require(maxPerRoute > 0) { "maxConnectionsPerRoute must be positive, was $maxPerRoute" }
        require(maxIdlePerRoute >= 0) { "maxIdleConnectionsPerRoute must not be negative, was $maxIdlePerRoute" }
        require(idleTimeoutMillis > 0) { "idleTimeout must be positive" }
        require(maxLifetimeMillis > 0) { "maxConnectionLifetime must be positive" }
    }
}

/**
 * Connection limits and keep-alive for HTTP/1.1: at most [PoolLimits.maxTotal] connections and [PoolLimits.maxPerRoute] per
 * route, idle ones included; requests beyond that wait in one FIFO queue (a waiter is served as soon as its route has an
 * idle connection or room, so a full route does not hold up others). When only the total is exhausted and another route has
 * idle connections, the oldest idle one is closed to make room. Idle connections expire after
 * [PoolLimits.idleTimeoutMillis] ([evictExpired]) and are never reused past [PoolLimits.maxLifetimeMillis]; a route without
 * connections or waiters is dropped from the map at once, so the map is bounded by the live connections and waiters.
 *
 * Every state change runs under a [SpinLock] and never suspends; connections are closed and waiters resumed outside it
 * (a waiter on `Dispatchers.Unconfined` resumes inline and may enter the pool again at once).
 */
internal class ConnectionPool<C : PooledConnection>(
    private val limits: PoolLimits,
    private val now: () -> Long,
) {
    private class Route<C>(
        val key: String,
    ) {
        /** Connections open to this route (in use, idle, or being opened under a permit). */
        var live = 0
        val idle = ArrayDeque<C>()
        var waiting = 0
    }

    /** Completed with an idle connection, or with null: a permit to open one, the slot already counted. */
    private class Waiter<C>(
        val route: String,
    ) {
        val result = CompletableDeferred<C?>()

        /** Under the lock, when it leaves the queue: whether it was granted [connection] (null: a permit) or failed by shutdown. */
        var granted = false
        var connection: C? = null
    }

    private val lock = SpinLock()
    private val routes = HashMap<String, Route<C>>()
    private val waiters = ArrayDeque<Waiter<C>>()
    private var total = 0
    private var shutDown = false

    /** Connections open, idle ones and permits included (tests). */
    val liveCount: Int get() = lock.withLock { total }

    /** Idle connections (tests). */
    val idleCount: Int get() = lock.withLock { routes.values.sumOf { it.idle.size } }

    /** Routes the pool tracks (tests: bounded by live connections and waiters). */
    val routeCount: Int get() = lock.withLock { routes.size }

    /** Requests waiting for a connection (tests). */
    val waiterCount: Int get() = lock.withLock { waiters.size }

    /**
     * An idle connection to [route], or null: the caller holds a permit and must open a connection, then [adopt] it or
     * [releasePermit] when that fails. Waits in FIFO order while the limits are reached. Cancellation while waiting
     * gives back whatever was granted meanwhile, so a slot is never lost or counted twice.
     */
    suspend fun acquire(route: String): C? {
        val toClose = ArrayList<C>()
        val waiter: Waiter<C>
        try {
            waiter =
                lock.withLock {
                    if (shutDown) throw ClientEngineClosedException()
                    val r = routes.getOrPut(route) { Route(route) }
                    takeIdle(r, toClose)?.let { return it }
                    if (grantPermit(r, toClose)) return null
                    Waiter<C>(route).also {
                        waiters.addLast(it)
                        r.waiting++
                    }
                }
        } finally {
            closeAll(toClose)
        }
        try {
            return waiter.result.await()
        } catch (e: CancellationException) {
            val granted =
                lock.withLock {
                    if (waiters.remove(waiter)) {
                        routes[route]?.let {
                            it.waiting--
                            prune(it)
                        }
                        null
                    } else {
                        // it left the queue under the lock (its result may still be on its way): hand back what it was given
                        waiter.takeIf { it.granted }
                    }
                }
            if (granted != null) {
                val c = granted.connection
                if (c == null) releasePermit(route) else release(c)
            }
            throw e
        }
    }

    /** Accounts [c], opened under a permit from [acquire]; from now on its [PooledConnection.close] gives the slot back. */
    fun adopt(c: C) {
        c.pool = this
    }

    /** A permit from [acquire] whose connection could not be opened. */
    fun releasePermit(route: String) {
        val toClose = ArrayList<C>()
        val served = ArrayList<Waiter<C>>()
        lock.withLock {
            routes[route]?.let { freeSlot(it) }
            dispatch(toClose, served)
        }
        resumeAll(served)
        closeAll(toClose)
    }

    /**
     * [c] finished an exchange and may be reused: it goes to the first waiter of its route, else to the idle list; it is
     * closed instead when it is no longer open, past its lifetime, beyond the idle limit, or when other routes wait for
     * room under the total limit. Returns whether it stays open (handed to a waiter or kept idle).
     */
    fun release(c: C): Boolean {
        if (c.closed) return false
        val toClose = ArrayList<C>()
        val served = ArrayList<Waiter<C>>()
        val kept =
            lock.withLock {
                val r = routes[c.route]
                if (shutDown || r == null || !c.isOpen || expired(c, now())) {
                    toClose += c
                    return@withLock false
                }
                val first = waiters.firstOrNull { it.route == c.route }
                if (first != null) {
                    waiters.remove(first)
                    r.waiting--
                    grant(first, c, served)
                    return@withLock true
                }
                if (waiters.isNotEmpty() || r.idle.size >= limits.maxIdlePerRoute) {
                    // waiters of other routes need the slot more than this route needs an idle connection
                    if (c.claimSlot()) freeSlot(r)
                    toClose += c
                    dispatch(toClose, served)
                    return@withLock false
                }
                c.idleSince = now()
                r.idle.addLast(c)
                true
            }
        resumeAll(served)
        closeAll(toClose)
        return kept
    }

    /** Called by [PooledConnection.close]: the slot comes back and the next waiter is served. */
    internal fun slotReturned(c: PooledConnection) {
        if (!c.claimSlot()) return
        val toClose = ArrayList<C>()
        val served = ArrayList<Waiter<C>>()
        lock.withLock {
            val r = routes[c.route]
            if (r != null) {
                r.idle.removeAll { it === c }
                freeSlot(r)
            }
            dispatch(toClose, served)
        }
        resumeAll(served)
        closeAll(toClose)
    }

    /**
     * Closes idle connections past the idle timeout or their lifetime, and ones the peer closed; returns the milliseconds
     * until the next idle connection expires, or null when none is idle.
     */
    fun evictExpired(): Long? {
        val toClose = ArrayList<C>()
        val served = ArrayList<Waiter<C>>()
        var next: Long? = null
        lock.withLock {
            val t = now()
            for (r in routes.values.toList()) {
                val it = r.idle.iterator()
                while (it.hasNext()) {
                    val c = it.next()
                    val idleEnd = saturatedAdd(c.idleSince, limits.idleTimeoutMillis)
                    val lifeEnd = saturatedAdd(c.createdAt, limits.maxLifetimeMillis)
                    if (t >= idleEnd || t >= lifeEnd || !c.isOpen) {
                        it.remove()
                        if (c.claimSlot()) freeSlotNoPrune(r)
                        toClose += c
                    } else {
                        val d = minOf(idleEnd, lifeEnd) - t
                        next = next?.let { n -> minOf(n, d) } ?: d
                    }
                }
                prune(r)
            }
            dispatch(toClose, served)
        }
        resumeAll(served)
        closeAll(toClose)
        return next
    }

    /**
     * Closes the idle connections and fails the waiters; later [acquire] calls fail. Both fail with Ktor's
     * [ClientEngineClosedException] (as the CIO engine), never a bare CancellationException a caller takes for its own.
     */
    fun shutdown() {
        val toClose = ArrayList<C>()
        val failed =
            lock.withLock {
                shutDown = true
                for (r in routes.values) {
                    for (c in r.idle) if (c.claimSlot()) freeSlotNoPrune(r)
                    toClose += r.idle
                    r.idle.clear()
                }
                val w = waiters.toList()
                waiters.clear()
                routes.values.forEach { it.waiting = 0 }
                routes.values.removeAll { it.live == 0 }
                w
            }
        failed.forEach { it.result.completeExceptionally(ClientEngineClosedException()) }
        closeAll(toClose)
    }

    // ---- under the lock ----

    private fun takeIdle(
        r: Route<C>,
        toClose: MutableList<C>,
    ): C? {
        val t = now()
        while (true) {
            val c = r.idle.removeLastOrNull() ?: return null // most recently used first: the likeliest to be alive
            if (c.isOpen && !expired(c, t)) return c
            if (c.claimSlot()) freeSlotNoPrune(r)
            toClose += c
        }
    }

    /** Counts a new connection to [r] when the limits allow, closing another route's oldest idle one if only the total is full. */
    private fun grantPermit(
        r: Route<C>,
        toClose: MutableList<C>,
    ): Boolean {
        if (r.live >= limits.maxPerRoute) return false
        if (total >= limits.maxTotal && !evictOldestIdle(toClose)) return false
        r.live++
        total++
        return true
    }

    private fun evictOldestIdle(toClose: MutableList<C>): Boolean {
        var oldest: Route<C>? = null
        for (r in routes.values) {
            val head = r.idle.firstOrNull() ?: continue
            if (oldest == null || head.idleSince < oldest.idle.first().idleSince) oldest = r
        }
        val r = oldest ?: return false
        val c = r.idle.removeFirst()
        if (c.claimSlot()) freeSlot(r) // never the requesting route: its idle list was emptied first
        toClose += c
        return true
    }

    /**
     * Serves waiters in FIFO order; one that cannot be served yet keeps its place, later ones of other routes may go. The
     * served ones are resumed by the caller once the lock is released ([resumeAll]).
     */
    private fun dispatch(
        toClose: MutableList<C>,
        served: MutableList<Waiter<C>>,
    ) {
        if (waiters.isEmpty()) return
        val it = waiters.iterator()
        while (it.hasNext()) {
            val w = it.next()
            val r = routes[w.route] ?: continue
            val idle = takeIdle(r, toClose)
            when {
                idle != null -> {
                    it.remove()
                    r.waiting--
                    grant(w, idle, served)
                }

                grantPermit(r, toClose) -> {
                    it.remove()
                    r.waiting--
                    grant(w, null, served)
                }
            }
        }
        routes.values.filter { it.live == 0 && it.waiting == 0 }.forEach { routes.remove(it.key) }
    }

    /** Records what [w] gets (a cancelled waiter hands it back from this record); its result is completed by [resumeAll]. */
    private fun grant(
        w: Waiter<C>,
        c: C?,
        served: MutableList<Waiter<C>>,
    ) {
        w.granted = true
        w.connection = c
        served += w
    }

    private fun freeSlot(r: Route<C>) {
        freeSlotNoPrune(r)
        prune(r)
    }

    private fun freeSlotNoPrune(r: Route<C>) {
        r.live--
        total--
    }

    private fun prune(r: Route<C>) {
        if (r.live == 0 && r.waiting == 0) routes.remove(r.key)
    }

    private fun expired(
        c: C,
        t: Long,
    ): Boolean = t >= saturatedAdd(c.createdAt, limits.maxLifetimeMillis)

    /** Outside the lock: hands the served waiters what [grant] recorded. */
    private fun resumeAll(l: List<Waiter<C>>) {
        for (w in l) w.result.complete(w.connection)
    }

    private fun closeAll(l: List<C>) {
        for (c in l) c.close()
    }

    private companion object {
        fun saturatedAdd(
            a: Long,
            b: Long,
        ): Long = if (b > Long.MAX_VALUE - a) Long.MAX_VALUE else a + b
    }
}
