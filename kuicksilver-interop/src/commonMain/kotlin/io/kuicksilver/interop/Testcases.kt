// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.EarlyDataState
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * What each QUIC Interop Runner test case asks of the endpoint. The runner hands the endpoint the case's
 * *endpoint name* (`testname`): `multiplexing`, `blackhole`, `amplificationlimit`, `transferloss`, `transfercorruption`,
 * `rebind-port`, `rebind-addr`, `ipv6`, `goodput` and `crosstraffic` all arrive as `transfer`; `longrtt`, `ecn` and the
 * server side of `keyupdate` as `handshake`; `handshakeloss` and `handshakecorruption` as `multiconnect`. `resumption` and
 * `zerortt` (ADR-0015) are the only plans that turn on session tickets and 0-RTT, which are opt-in: the server issues
 * tickets and accepts early data, the client keeps the first connection's ticket and resumes it on a second connection
 * (`zerortt`: with the remaining requests in 0-RTT). Unsupported cases exit 127: `connectionmigration` (the server would
 * have to offer a preferred address, decision B-20), `versionnegotiation`.
 */
internal object Testcases {
    val v1: List<VersionProfile> = listOf(VersionProfile.V1)
    private val v2first: List<VersionProfile> = listOf(VersionProfile.V2, VersionProfile.V1)
    val supported: Set<String> = setOf("handshake", "transfer", "chacha20", "multiconnect", "keyupdate", "retry", "v2", "ecn", "http3", "resumption", "zerortt")
    private val resuming = setOf("resumption", "zerortt")

    /**
     * [http3]: the `http3` case — ALPN `h3`, one HTTP/3 transaction per file (`H3InteropClient`/`H3InteropServer`); everything else is `hq-interop`.
     * [earlyData]: `Allowed` for `resumption` and `zerortt` (the endpoint keeps tickets), else `Disabled`; the first request then goes over its
     * own connection and the rest over a second one that resumes, in 0-RTT when [zeroRtt].
     */
    class ClientPlan(val quic: QuicConfig, val cipherSuites: CipherSuites, val keyUpdateAfterBytes: Long?, val connectionPerRequest: Boolean, val http3: Boolean = false, val earlyData: EarlyDataState = EarlyDataState.Disabled, val zeroRtt: Boolean = false)
    /**
     * [handshakeTimeout]: 30 s instead of the library's 10 s. In `amplificationlimit` the server spends its three-times budget on the
     * first flight and, per RFC 9002 section 6.2.2.1, arms no PTO; the client's PTO backoff after the six dropped datagrams reaches
     * the server only after 8 to 14 s with ngtcp2, depending on its RTT sample.
     */
    class ServerPlan(val versions: List<VersionProfile>, val admission: ConnectionAdmission, val cipherSuites: CipherSuites, val http3: Boolean = false, val handshakeTimeout: Duration = 30.seconds, val earlyData: Boolean = false)

    fun client(testcase: String): ClientPlan? {
        if (testcase !in supported) return null
        // v2: both sides prefer v2; the client's first flight is v1 and the server upgrades it (RFC 9368 section 2.3)
        // 30 s like the server plan: under handshakecorruption a two-datagram ClientHello (ML-KEM key share) can need more than four PTO rounds
        val quic = quicConfig { handshakeTimeout = 30.seconds; if (testcase == "v2") { versions = v2first; initialVersion = VersionProfile.V1 } }
        return ClientPlan(quic, suites(testcase), keyUpdateAfterBytes = if (testcase == "keyupdate") 1L shl 18 else null, connectionPerRequest = testcase == "multiconnect", http3 = testcase == "http3",
            earlyData = if (testcase in resuming) EarlyDataState.Allowed else EarlyDataState.Disabled, zeroRtt = testcase == "zerortt")
    }
    fun server(testcase: String): ServerPlan? {
        if (testcase !in supported) return null
        return ServerPlan(if (testcase == "v2") v2first else v1, if (testcase == "retry") ConnectionAdmission.AlwaysRetry else ConnectionAdmission.default(), suites(testcase), http3 = testcase == "http3", earlyData = testcase in resuming)
    }
    private fun suites(testcase: String): CipherSuites = if (testcase == "chacha20") CipherSuites(listOf(CipherSuites.CHACHA20_POLY1305)) else CipherSuites.Default
}
