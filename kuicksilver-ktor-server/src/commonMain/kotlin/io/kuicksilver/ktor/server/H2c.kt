// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select

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
     * `CleartextHttp2ServerUpgradeHandler` serve both on one port too.
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
 * the wait ([H2cMode.WithHttp11]: the request-head deadline).
 */
@OptIn(InternalAPI::class)
internal suspend fun ByteReadChannel.startsWithH2Preface(): Boolean {
    var matched = 0
    while (matched < H2_CLIENT_PREFACE.size) {
        if (!awaitContent(matched + 1)) return false
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
 * Whether the octets already here are the whole HTTP/2 client connection preface, without waiting for any: false while
 * fewer than its 24 octets arrived, at the first that differs, or when the input failed.
 */
@OptIn(InternalAPI::class)
private fun ByteReadChannel.prefaceArrived(): Boolean {
    if (closedCause != null) return false
    val seen = readBuffer.peek()
    for (octet in H2_CLIENT_PREFACE) {
        if (seen.exhausted() || seen.readByte() != octet) return false
    }
    return true
}

/**
 * [startsWithH2Preface], or false as soon as [stop] completes first: a stopping server reads no further request, so a
 * connection still sending its first octets goes to HTTP/1.1 instead of holding the stop for the request-head deadline.
 * When the stop wins, the check is ended (joined, so nothing else reads the input meanwhile) and the octets looked at
 * again: a whole preface that came with the stop is HTTP/2 all the same (RFC 9113 section 3.3: prior knowledge), and
 * the HTTP/2 connection ends it with GOAWAY (section 6.8), never an HTTP/1.1 answer the client cannot read. The check
 * consumes nothing, so dropping it loses no octet.
 */
internal suspend fun ByteReadChannel.startsWithH2PrefaceUnless(
    stop: Job,
    checkForTest: (suspend (ByteReadChannel) -> Unit)? = null,
): Boolean =
    coroutineScope {
        val check =
            async {
                checkForTest?.invoke(this@startsWithH2PrefaceUnless)
                startsWithH2Preface()
            }
        try {
            select {
                check.onAwait { it }
                stop.onJoin {
                    check.cancelAndJoin()
                    prefaceArrived()
                }
            }
        } finally {
            check.cancel()
        }
    }
