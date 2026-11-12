// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.io.IOException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/*
 * Happy Eyeballs version 2 (RFC 8305) for the engines' connects, TCP and QUIC: the two families asked for separately and
 * raced as they arrive (section 3), every address sorted by RFC 6724 and the families interleaved (section 4, the sort in
 * AddressSelection.kt), attempts one connection attempt delay apart or as soon as the previous one failed (section 5), late
 * answers joining the race (section 6), and on an IPv6-only network the NAT64 timing of section 7 (the synthesis is the
 * resolution's: the Ktor client's RequestDns). Name lookups: NameResolution.kt.
 */

/**
 * An IP address and a TCP port, for the engines' connects: [bytes] holds 4 (IPv4) or 16 (IPv6) bytes in network order,
 * [scopeId] the zone of a link-local IPv6 address (0: none).
 */
@InternalKuicksilverApi
public class TcpAddress(
    bytes: ByteArray,
    /** The TCP port, 0..65535. */
    public val port: Int,
    /** The IPv6 scope (zone) id; 0 for IPv4 and for addresses without one. */
    public val scopeId: Int = 0,
) {
    private val ip: ByteArray = bytes.copyOf()

    init {
        require(ip.size == 4 || ip.size == 16) { "an IP address has 4 or 16 bytes, not ${ip.size}" }
        require(port in 0..0xffff) { "port out of range: $port" }
    }

    /** The address bytes (a copy): 4 for IPv4, 16 for IPv6. */
    public val bytes: ByteArray get() = ip.copyOf()

    /** Whether this is an IPv6 address. */
    public val isIpv6: Boolean get() = ip.size == 16

    /** The address as text without brackets: dotted decimal, or RFC 5952 IPv6 with `%scope` when it has one. */
    public val hostText: String get() = ipText(ip) + if (scopeId != 0) "%${scopeId.toUInt()}" else ""

    /** The same address with [port]. */
    public fun withPort(port: Int): TcpAddress = if (port == this.port) this else TcpAddress(ip, port, scopeId)

    override fun equals(other: Any?): Boolean =
        other is TcpAddress && other.port == port && other.scopeId == scopeId && other.ip.contentEquals(ip)

    override fun hashCode(): Int = (ip.contentHashCode() * 31 + port) * 31 + scopeId

    override fun toString(): String = if (isIpv6) "[$hostText]:$port" else "$hostText:$port"
}

/**
 * The four bytes of a dotted-decimal IPv4 literal (each octet 0..255, at most three digits, no leading zero), or null.
 * An octet with a leading zero (`010`) is octal to `inet_aton`, `getaddrinfo`, curl and WHATWG URLs (8, not 10): such a
 * string is left to the platform as before, so the address connected to is the one those parsers (and any allow or
 * deny list built on them) see.
 */
@InternalKuicksilverApi
public fun parseIpv4Literal(name: String): ByteArray? {
    val parts = name.split('.')
    if (parts.size != 4) return null
    val out = ByteArray(4)
    for ((i, p) in parts.withIndex()) {
        if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' } || (p.length > 1 && p[0] == '0')) return null
        val v = p.toInt()
        if (v > 255) return null
        out[i] = v.toByte()
    }
    return out
}

/**
 * Opens a TCP connection to exactly [address], as [connectTcp] does for one resolved address (on Kotlin/Native a socket
 * of this module, not ktor-network's native connect: Ktor issue KTOR-10017, security, under coordinated disclosure).
 * Fails with an [IOException] when the connection cannot be made; a cancelled connect closes its socket.
 */
@InternalKuicksilverApi
public expect suspend fun connectTcpAddress(
    selector: SelectorManager,
    address: TcpAddress,
): Socket

/**
 * Opens a TCP connection to [host] and [port] with Happy Eyeballs (RFC 8305, [raceAddresses]): [resolution] gives the
 * addresses one family at a time, [order] sorts and interleaves those not tried yet (RFC 6724 and RFC 8305 section 4 by
 * default), and a new attempt starts every [attemptDelay] or as soon as the previous one failed; the first connected socket
 * is returned, the other attempts are cancelled and sockets that connected too are closed. [Duration.INFINITE] tries the
 * addresses one after another. The race has no deadline of its own: the caller bounds it (the engines' connect timeout).
 */
@InternalKuicksilverApi
public suspend fun connectTcpRacing(
    selector: SelectorManager,
    host: String,
    port: Int,
    attemptDelay: Duration,
    resolution: AddressResolution = SystemResolution(host, port),
    order: (List<TcpAddress>) -> List<TcpAddress> = defaultOrder(),
): Socket = raceAddresses(host, resolution, attemptDelay, order, connect = { connectTcpAddress(selector, it) }, close = { it.close() })

/** The order of RFC 8305 section 4: an RFC 6724 sort ([DestinationSort], one per race), then the families interleaved. */
@InternalKuicksilverApi
public fun defaultOrder(sort: DestinationSort = DestinationSort()): (List<TcpAddress>) -> List<TcpAddress> =
    { interleaveFamilies(sort.sort(it)) }

/**
 * The Resolution Delay of RFC 8305 section 3: "The recommended value for the Resolution Delay is 50 milliseconds." An IPv4
 * answer that comes first waits this long for the IPv6 one before the first attempt starts.
 */
@InternalKuicksilverApi
public val RESOLUTION_DELAY: Duration = 50.milliseconds

/**
 * RFC 8305 section 5: "a subsequent connection MUST NOT be started within 10 milliseconds of the previous attempt", also
 * when the previous attempt failed sooner.
 */
@InternalKuicksilverApi
public val MIN_ATTEMPT_GAP: Duration = 10.milliseconds

/**
 * The Last Resort Local Synthesis Delay of RFC 8305 section 7.2, "recommended to be 2 seconds": on an IPv6-only network,
 * how long after the last IPv6 attempt started the IPv4 addresses are asked for, to be synthesized.
 */
@InternalKuicksilverApi
public val LAST_RESORT_SYNTHESIS_DELAY: Duration = 2.seconds

/**
 * The race of RFC 8305 over a static list [addrs], tried in the given order (no sort): [raceAddresses] with every address
 * known at the start.
 */
internal suspend fun <S> happyEyeballs(
    addrs: List<TcpAddress>,
    attemptDelay: Duration,
    connect: suspend (TcpAddress) -> S,
    close: (S) -> Unit,
): S {
    require(addrs.isNotEmpty()) { "no address to connect to" }
    return raceAddresses("", null, attemptDelay, { it }, connect, close, known = addrs)
}

private sealed interface RaceEvent {
    class Answer(
        val ipv6: Boolean,
        val result: Result<List<TcpAddress>>,
    ) : RaceEvent

    class Failed(
        val cause: Throwable,
    ) : RaceEvent

    /** A timer of the attempt numbered [attempt]: the attempt delay, or the 10 ms gap after its start. */
    class AttemptDelayOver(
        val attempt: Int,
    ) : RaceEvent

    class GapOver(
        val attempt: Int,
    ) : RaceEvent

    data object ResolutionDelayOver : RaceEvent

    data object LastResort : RaceEvent
}

private enum class FamilyState { NotAsked, Pending, Positive, Negative }

/**
 * Happy Eyeballs version 2 (RFC 8305) over the addresses [resolution] gives for [host]: each attempt is a child coroutine
 * running [connect], the first result wins, the other attempts are cancelled and a result that arrives anyway (a connect
 * that completed as it was cancelled) goes to [close]. When every attempt failed and no answer is outstanding, the last
 * failure is thrown with the earlier ones suppressed (a failed lookup is thrown when there was nothing to try). Cancelling
 * the caller cancels every attempt and lookup, and closes a winner it can no longer return.
 *
 * - Section 3: the IPv6 and IPv4 addresses are asked for at once, IPv6 first. "if a positive AAAA response ... is received
 *   first, the first IPv6 connection attempt is immediately started"; an IPv4 answer that comes first waits
 *   [resolutionDelay] for the IPv6 one, and goes ahead at once when the IPv6 answer is negative or failed. An answer that
 *   comes while attempts run joins them: "the newly received IPv6 addresses are incorporated into the list of available
 *   candidate addresses".
 * - Section 4 and section 6: before each attempt the addresses received and not tried yet are put in [order] (an RFC 6724
 *   sort and the families interleaved: [defaultOrder]); "If an address is added to the list, it should be sorted into the
 *   list of addresses not yet attempted according to the rules above".
 * - Section 5: "one connection attempt to a single address is started first, followed by the others in the list, one at a
 *   time": the next one when [attemptDelay] has passed since the last start, or when an attempt failed, never within
 *   [MIN_ATTEMPT_GAP] of the previous start ([Duration.INFINITE]: only on failure).
 * - Section 7: on an IPv6-only network ([AddressResolution.ipv6Only]) IPv4 is asked for only when the IPv6 answer was
 *   negative or failed, or as the last resort [lastResortDelay] after the last attempt started without a connection (or
 *   at once when all of them failed); the resolution synthesizes the answer.
 *
 * [known] (with no [resolution]): a list given up front, both families settled. [failures] collects every attempt's failure
 * as it comes (a caller whose own timeout ends the race still has them); when every attempt failed, [chooseFailure] picks
 * the one thrown, the others suppressed in it (each attempt's failure is its own; a lookup's failure, which a request's
 * other races share, is never changed: a fresh [IOException] carries it).
 */
@InternalKuicksilverApi
@OptIn(ExperimentalCoroutinesApi::class)
public suspend fun <S> raceAddresses(
    host: String,
    resolution: AddressResolution?,
    attemptDelay: Duration,
    order: (List<TcpAddress>) -> List<TcpAddress>,
    connect: suspend (TcpAddress) -> S,
    close: (S) -> Unit,
    resolutionDelay: Duration = RESOLUTION_DELAY,
    lastResortDelay: Duration = LAST_RESORT_SYNTHESIS_DELAY,
    known: List<TcpAddress> = emptyList(),
    failures: MutableList<Throwable>? = null,
    chooseFailure: (List<Throwable>) -> Throwable = { it.last() },
): S {
    require(attemptDelay.isPositive()) { "attemptDelay must be positive, was $attemptDelay" }
    require(resolution != null || known.isNotEmpty()) { "no address to connect to" }
    // outside the scope: a caller cancelled after an attempt won (while the losers wind down) still closes the winner
    val won = CompletableDeferred<S>()
    try {
        coroutineScope {
            val events = Channel<RaceEvent>(Channel.UNLIMITED)
            val received = ArrayList<TcpAddress>(known.distinct())
            val attempted = HashSet<TcpAddress>()
            val errors = ArrayList<Throwable>()
            val lookupErrors = ArrayList<Throwable>()
            val ipv6Only = resolution?.ipv6Only == true
            var v6 = if (resolution == null) FamilyState.Positive else FamilyState.Pending
            var v4 =
                if (resolution == null) {
                    FamilyState.Positive
                } else if (ipv6Only) {
                    FamilyState.NotAsked
                } else {
                    FamilyState.Pending
                }
            var started = 0
            var inFlight = 0
            var delayOver = true // the attempt delay since the last start has passed (or nothing started)
            var gapOpen = true // MIN_ATTEMPT_GAP since the last start has passed
            var startWhenGapOpens = false
            var resolutionDelayOver = false
            var resolutionTimer: Job? = null
            var attemptTimer: Job? = null
            var gapTimer: Job? = null
            var lastResortTimer: Job? = null

            fun timer(
                d: Duration,
                event: RaceEvent,
            ): Job =
                launch {
                    delay(d)
                    events.trySend(event)
                }

            fun ask(ipv6: Boolean) {
                // undispatched: the query is on its way when this returns, the IPv6 one before the IPv4 one
                launch(start = CoroutineStart.UNDISPATCHED) {
                    val result =
                        try {
                            Result.success(resolution!!.addresses(ipv6))
                        } catch (e: CancellationException) {
                            currentCoroutineContext().ensureActive() // the race's own end; else the lookup's (a timeout)
                            Result.failure(e)
                        } catch (e: Throwable) {
                            Result.failure(e)
                        }
                    events.trySend(RaceEvent.Answer(ipv6, result))
                }
            }

            // the whole list in order, then the addresses not tried yet: a late answer is sorted in among those, and the
            // families keep alternating from where the attempts got to
            fun pending(): List<TcpAddress> = order(received).filter { it !in attempted }

            fun firstAllowed(): Boolean =
                started > 0 || v6 == FamilyState.Positive ||
                    (v4 == FamilyState.Positive && (v6 == FamilyState.Negative || resolutionDelayOver))

            fun startNext() {
                val next = pending().firstOrNull() ?: return
                attempted += next
                started++
                inFlight++
                delayOver = false
                gapOpen = false
                startWhenGapOpens = false
                attemptTimer?.cancel()
                if (!attemptDelay.isInfinite()) attemptTimer = timer(attemptDelay, RaceEvent.AttemptDelayOver(started))
                gapTimer?.cancel()
                gapTimer = timer(MIN_ATTEMPT_GAP, RaceEvent.GapOver(started))
                launch {
                    val s =
                        try {
                            connect(next)
                        } catch (e: CancellationException) {
                            // the race's own end; else the attempt's (a timeout inside it), a failure like any other
                            currentCoroutineContext().ensureActive()
                            events.trySend(RaceEvent.Failed(e))
                            return@launch
                        } catch (e: Throwable) {
                            events.trySend(RaceEvent.Failed(e))
                            return@launch
                        }
                    // a loser that connected after all: nobody takes its socket
                    if (!won.complete(s)) runCatching { close(s) }
                }
                // section 7.2: "The timer is started when the last connection attempt is fired."
                if (ipv6Only && v4 == FamilyState.NotAsked && v6 != FamilyState.Pending && pending().isEmpty()) {
                    lastResortTimer?.cancel()
                    lastResortTimer = timer(lastResortDelay, RaceEvent.LastResort)
                }
            }

            // [due]: an attempt failed or the attempt delay passed, so the next one may start now
            fun maybeStart(due: Boolean) {
                if (!firstAllowed()) return
                if (!(due || inFlight == 0 || delayOver)) return
                if (!gapOpen) {
                    startWhenGapOpens = true
                    return
                }
                startNext()
            }

            fun askIpv4() {
                if (v4 != FamilyState.NotAsked) return
                v4 = FamilyState.Pending
                lastResortTimer?.cancel()
                ask(false)
            }

            if (resolution != null) {
                ask(true)
                if (!ipv6Only) ask(false)
            } else {
                maybeStart(due = true)
            }
            while (!won.isCompleted) {
                if (inFlight == 0 && v6 != FamilyState.Pending && v4 != FamilyState.Pending && pending().isEmpty()) {
                    if (v4 == FamilyState.NotAsked) {
                        askIpv4() // section 7.2: every IPv6 attempt failed already, nothing to wait for
                        continue
                    }
                    throw raceFailure(host, errors, lookupErrors, chooseFailure)
                }
                select<Unit> {
                    won.onJoin {}
                    events.onReceive { e ->
                        when (e) {
                            is RaceEvent.Answer -> {
                                val found =
                                    e.result
                                        .getOrNull()
                                        .orEmpty()
                                        .filter { it !in received }
                                e.result.exceptionOrNull()?.let { lookupErrors += it }
                                received += found
                                val state =
                                    if (e.result
                                            .getOrNull()
                                            .orEmpty()
                                            .isNotEmpty()
                                    ) {
                                        FamilyState.Positive
                                    } else {
                                        FamilyState.Negative
                                    }
                                if (e.ipv6) {
                                    v6 = state
                                    if (state == FamilyState.Negative && ipv6Only) askIpv4()
                                } else {
                                    v4 = state
                                    if (state == FamilyState.Positive && v6 == FamilyState.Pending && started == 0 &&
                                        resolutionTimer == null
                                    ) {
                                        resolutionTimer = timer(resolutionDelay, RaceEvent.ResolutionDelayOver)
                                    }
                                }
                                if (found.isNotEmpty() || started == 0) maybeStart(due = false)
                            }

                            is RaceEvent.Failed -> {
                                errors += e.cause
                                failures?.add(e.cause)
                                inFlight--
                                maybeStart(due = true)
                            }

                            is RaceEvent.AttemptDelayOver -> {
                                if (e.attempt == started) {
                                    delayOver = true
                                    maybeStart(due = true)
                                }
                            }

                            is RaceEvent.GapOver -> {
                                if (e.attempt == started) {
                                    gapOpen = true
                                    if (startWhenGapOpens) maybeStart(due = true)
                                }
                            }

                            RaceEvent.ResolutionDelayOver -> {
                                resolutionDelayOver = true
                                maybeStart(due = false)
                            }

                            RaceEvent.LastResort -> {
                                askIpv4()
                            }
                        }
                    }
                }
            }
            coroutineContext.cancelChildren()
        }
    } catch (e: Throwable) {
        if (won.isCompleted) runCatching { close(won.getCompleted()) }
        throw e
    }
    return won.getCompleted()
}

/**
 * The race's failure: the attempt failure [chooseFailure] picks, the others suppressed in it (they are the race's own);
 * else the lookups' (shared with the request's other races, so never changed: one alone as it is, several as the causes
 * of a fresh [IOException]); else "no address".
 */
private fun raceFailure(
    host: String,
    errors: List<Throwable>,
    lookupErrors: List<Throwable>,
    chooseFailure: (List<Throwable>) -> Throwable,
): Throwable {
    if (errors.isNotEmpty()) {
        val chosen = chooseFailure(errors)
        for (e in errors.distinct()) if (e !== chosen) chosen.addSuppressed(e)
        return chosen
    }
    if (lookupErrors.isNotEmpty()) return sharedFailures(host, lookupErrors.distinct())
    return IOException("$host resolved to no address")
}

/** [shared] failures as one throwable without changing any of them: the only one, or a fresh [IOException] with them. */
internal fun sharedFailures(
    host: String,
    shared: List<Throwable>,
): Throwable {
    if (shared.size == 1) return shared.single()
    return IOException("$host could not be resolved", shared.last()).also { e -> shared.dropLast(1).forEach { e.addSuppressed(it) } }
}

private fun Byte.u(): Int = toInt() and 0xff

/**
 * The text of the IPv4 (4 bytes) or IPv6 (16 bytes) address [ip]: dotted decimal, or RFC 5952 (lower-case hex, the longest
 * run of zero groups as `::`, an IPv4-mapped address as `::ffff:a.b.c.d`).
 */
internal fun ipText(ip: ByteArray): String {
    if (ip.size == 4) return ip.joinToString(".") { it.u().toString() }
    // an IPv4-mapped peer of a dual-stack listener, written as inet_ntop (and ktor-network) does
    if ((0 until 10).all { ip[it].toInt() == 0 } && ip[10].u() == 0xff && ip[11].u() == 0xff) {
        return "::ffff:" + ipText(ip.copyOfRange(12, 16))
    }
    val groups = IntArray(8) { (ip[2 * it].u() shl 8) or ip[2 * it + 1].u() }
    var bestStart = -1
    var bestLength = 1 // RFC 5952 4.2.2: a single zero group is not compressed
    var i = 0
    while (i < 8) {
        if (groups[i] != 0) {
            i++
            continue
        }
        var j = i
        while (j < 8 && groups[j] == 0) j++
        if (j - i > bestLength) {
            bestStart = i
            bestLength = j - i
        }
        i = j
    }
    if (bestStart < 0) return groups.joinToString(":") { it.toString(16) }
    val head = (0 until bestStart).joinToString(":") { groups[it].toString(16) }
    val tail = (bestStart + bestLength until 8).joinToString(":") { groups[it].toString(16) }
    return "$head::$tail"
}
