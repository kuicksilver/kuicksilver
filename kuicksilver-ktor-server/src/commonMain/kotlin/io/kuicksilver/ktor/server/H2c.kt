// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.TimeMark

/**
 * HTTP/2 over cleartext TCP ("h2c", RFC 9113 section 3.3: prior knowledge, no ALPN, no TLS) on a plain connector
 * ([KuicksilverPlainConnector.Builder.h2c], `kuicksilver.h2c` in `EngineMain`): for a server behind a TLS-terminating proxy
 * or load balancer, inside a service mesh whose sidecar does the TLS, and for gRPC between services (ADR-0018).
 *
 * Cleartext: nothing authenticates the client nor protects the bytes (CWE-319). Serve h2c only where the network between
 * the two ends is trusted or protected by other means (a loopback hop, a private network, a sidecar's mTLS); docs/guide/ktor.md,
 * "h2c". `Upgrade: h2c` (RFC 7540 section 3.2) is never taken: RFC 9113 section 3.1 deprecates it, and an HTTP/1.1 request
 * that offers it is served as HTTP/1.1 ([WithHttp11]) as any request with an `Upgrade` the server does not take (RFC 9110
 * section 7.8). Every HTTP/2 limit, deadline and flood defence of a TLS connector holds on h2c unchanged.
 */
@ExperimentalKuicksilverApi
public enum class H2cMode {
    /** No HTTP/2 (the default): HTTP/1.1 only; a client's `PRI * HTTP/2.0` preface is answered 505, as before 0.3.0. */
    Off,

    /**
     * HTTP/1.1 and h2c on the same port: a connection whose first 24 octets are the HTTP/2 client connection preface
     * (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`, RFC 9113 section 3.4) is HTTP/2, any other HTTP/1.1. The octets are looked at as
     * they arrive and none is consumed: the first one that differs from the preface hands the connection to HTTP/1.1 at
     * once (a request shorter than the preface is never held back), and the wait for them is part of the first request
     * head's deadline (`requestHeaderTimeoutSeconds`), as on HTTP/1.1. Go's `golang.org/x/net/http2/h2c` handler and Netty's
     * `CleartextHttp2ServerUpgradeHandler` serve both on one port too. When the server stops during the wait, a connection
     * that sent nothing yet is closed at once; one that sent the start of the preface is still waited for, within the
     * same deadline (and the stop's grace period), as a request head that started on HTTP/1.1 is: a whole preface is
     * HTTP/2, which serves the requests that came with it and ends with the graceful GOAWAY (RFC 9113 section 6.8), and
     * the first octet that differs hands the connection to HTTP/1.1, which answers that request with `Connection: close`.
     * A client that stops part way is closed at the deadline (as HTTP/1.1, so with 408).
     */
    WithHttp11,

    /**
     * h2c only (as a gRPC server's port): every connection is HTTP/2 with prior knowledge. A client that sends anything
     * but the preface (an HTTP/1.1 request) gets a connection error of type PROTOCOL_ERROR (RFC 9113 section 3.4: GOAWAY,
     * then the close), never an HTTP/1.1 answer.
     */
    Only,
}

/** The HTTP/2 client connection preface (RFC 9113 section 3.4). */
private val H2_CLIENT_PREFACE: ByteArray = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".encodeToByteArray()

/**
 * Whether this channel starts with the HTTP/2 client connection preface (RFC 9113 section 3.4), consuming nothing: true once
 * its 24 octets arrived and match, false at the first octet that differs or at the end of the input, whichever comes first.
 * It waits for one more octet only while all those seen match, so at most the 24 octets of the preface; the caller bounds
 * the wait ([H2cMode.WithHttp11]: the request-head deadline). [onOctet] runs each time octets are there to look at.
 */
@OptIn(InternalAPI::class)
internal suspend fun ByteReadChannel.startsWithH2Preface(onOctet: (() -> Unit)? = null): Boolean {
    var matched = 0
    while (matched < H2_CLIENT_PREFACE.size) {
        if (!awaitContent(matched + 1)) return false
        onOctet?.invoke()
        val seen = readBuffer.peek()
        seen.skip(matched.toLong())
        while (matched < H2_CLIENT_PREFACE.size && !seen.exhausted()) {
            if (seen.readByte() != H2_CLIENT_PREFACE[matched]) return false
            matched++
        }
    }
    return true
}

/**
 * Whether at least [min] octets are in this channel now, without waiting: those ktor has already taken from the socket,
 * moved into the read buffer from the writer's flush buffer when they sit there (awaitContent moves them and returns
 * without suspending), so octets flushed while nobody was reading count too. False when fewer are there, at the end of
 * the input, or when the input failed (a channel may report its failure while octets it took before are still readable:
 * the caller's next reader sees them and the failure). Bytes still in the socket, not read by ktor yet, are not seen.
 * Only while no other coroutine reads this channel.
 */
internal suspend fun ByteReadChannel.hasAtOnce(min: Int): Boolean =
    coroutineScope {
        val probe =
            async(start = CoroutineStart.UNDISPATCHED) {
                try {
                    awaitContent(min)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    false
                }
            }
        if (probe.isCompleted) {
            probe.await()
        } else {
            probe.cancel()
            false
        }
    }

/** Whether the whole HTTP/2 client connection preface is in this channel now ([hasAtOnce]), consuming nothing. */
@OptIn(InternalAPI::class)
internal suspend fun ByteReadChannel.h2PrefaceAtOnce(): Boolean {
    if (!hasAtOnce(H2_CLIENT_PREFACE.size)) return false
    val seen = readBuffer.peek()
    for (octet in H2_CLIENT_PREFACE) {
        if (seen.exhausted() || seen.readByte() != octet) return false
    }
    return true
}

/**
 * [startsWithH2Preface], except that a connection that has sent nothing when [stop] completes is waited for only until
 * [firstOctetBy] (a new connection's first request may be on its way; the engine's NEW_CONNECTION_FIRST_BYTE after its
 * acceptance): false then, and HTTP/1.1, whose own wait for a new connection's first byte has the same end, closes it as
 * idle. A connection that has sent its first octet is a request head that started
 * (HTTP/1.1 would wait for the rest of it too), so the check goes on to its end, within the caller's bound (the
 * request-head deadline; the stop's grace period cancels it): a whole preface is HTTP/2 (RFC 9113 section 3.3: prior
 * knowledge), whose connection serves what came with it under the graceful GOAWAY (section 6.8), never an HTTP/1.1 answer
 * the client cannot read. When the stop wins the race, the check is ended (joined, so nothing else reads the input
 * meanwhile) unless it had seen an octet, and the input looked at again ([hasAtOnce], which also takes octets flushed
 * into the channel while the check was not reading): any octet there starts the check over. It consumes nothing, so
 * dropping it loses no octet.
 */
internal suspend fun ByteReadChannel.startsWithH2PrefaceUnless(
    stop: Job,
    firstOctetBy: TimeMark? = null,
    checkForTest: (suspend (ByteReadChannel, Job) -> Unit)? = null,
): Boolean =
    coroutineScope {
        // completed once the check saw an octet: the connection has started to send, and is no longer idle
        val started = Job()
        val check =
            async {
                checkForTest?.invoke(this@startsWithH2PrefaceUnless, stop)
                startsWithH2Preface { started.complete() }
            }
        try {
            select {
                check.onAwait { it }
                stop.onJoin {
                    if (started.isCompleted) {
                        check.await()
                    } else {
                        check.cancelAndJoin()
                        // a new connection's first octet may still be on its way: it gets until firstOctetBy, as HTTP/1.1
                        // gives a new connection's first request (awaitContent takes no octet; one that came as the bound
                        // fired is looked at again)
                        val left = firstOctetBy?.let { -it.elapsedNow() } ?: Duration.ZERO
                        if (left > Duration.ZERO) withTimeoutOrNull(left) { awaitContent(1) }
                        hasAtOnce(1) && startsWithH2Preface()
                    }
                }
            }
        } finally {
            check.cancel()
            started.cancel()
        }
    }
