// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import io.kuicksilver.tls.tlsConfig
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Ready-made runs: a transfer over one or more streams whose bytes are checked for order and exactness. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
public object SimScenario {
    private val acceptAll = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) }

    /** A TLS pair for [io.kuicksilver.quic.NullCryptoProvider] runs; [identity] is only needed for configuration validation. */
    public fun nullTls(identity: TlsIdentity): Pair<TlsConfig, TlsConfig> =
        tlsConfig(TlsRole.Client) {
            alpn = listOf("sim")
            serverName = "sim.test"
            trust = acceptAll
        } to
            tlsConfig(TlsRole.Server) {
                alpn = listOf("sim")
                this.identity = identity
            }

    /** Default TLS pair: a throwaway identity is not available in commonMain, so callers pass one; [transfer] uses [defaultTls] when set. */
    public var defaultTls: (() -> Pair<TlsConfig, TlsConfig>)? = null

    private fun byteAt(
        stream: Int,
        offset: Long,
    ): Byte = ((offset * 7 + stream * 13 + (offset ushr 8)) and 0xff).toByte()

    /** Moves [bytes] from the client to the server over [streams] streams; [atBytes] runs [midway] once that many bytes have been read (scenario hooks such as a NAT rebind). */
    public fun transfer(
        sim: Simulator,
        bytes: Int,
        streams: Int = 1,
        connection: SimConnection? = null,
        dropLastClientDatagram: Boolean = false,
        limit: Duration = 120.seconds,
        atBytes: Long = -1L,
        midway: () -> Unit = {},
        fromServer: Boolean = false,
        onStep: () -> Unit = {},
    ): SimResult {
        val conn =
            connection
                ?: run {
                    val (c, s) = defaultTls?.invoke() ?: error("SimScenario.defaultTls is not set")
                    sim.connect(tlsClient = c, tlsServer = s)
                }
        val ids = LongArray(streams) { -1 }
        val written = LongArray(streams)
        val read = LongArray(streams)
        val per = bytes / streams
        val chunk = ByteArray(16384)
        val inBuf = ByteArray(16384)
        var mismatch: String? = null
        var dropArmed = dropLastClientDatagram
        var midwayDone =
            atBytes < 0
        return sim
            .runUntil(limit) {
                onStep()
                // [fromServer]: the server writes and the client reads (a download, as the interop runner's transfer and rebind cases)
                val c = if (fromServer) conn.server ?: return@runUntil false else conn.client
                val s = if (fromServer) conn.client else conn.server
                if (conn.handshakeDone) {
                    for (i in 0 until streams) {
                        if (ids[i] < 0) ids[i] = c.openStream(true, StreamPriority.Default)
                        if (ids[i] >= 0 && written[i] < per) {
                            val n = minOf(chunk.size.toLong(), per - written[i]).toInt()
                            for (k in 0 until n) {
                                chunk[k] =
                                    byteAt(i, written[i] + k)
                            }
                            val fin = written[i] + n == per.toLong()
                            if (fin && dropArmed) {
                                sim.dropNextClientToServer = true
                                dropArmed = false
                            }
                            written[i] += c.writeStream(ids[i], chunk, 0, n, fin)
                        }
                    }
                    if (s != null) {
                        for (i in 0 until streams) {
                            if (ids[i] < 0) continue
                            while (true) {
                                val n = s.readStream(ids[i], inBuf, 0, inBuf.size)
                                if (n <= 0) break
                                for (k in 0 until n) {
                                    if (inBuf[k] != byteAt(i, read[i] + k) &&
                                        mismatch == null
                                    ) {
                                        mismatch = "stream $i byte ${read[i] + k}"
                                    }
                                }
                                read[i] += n
                                sim.progress += n
                            }
                        }
                    }
                    if (!midwayDone && read.sum() >= atBytes) {
                        midwayDone = true
                        midway()
                    }
                }
                mismatch == null && read.all { it == per.toLong() } && streams > 0
            }.let { r ->
                if (mismatch !=
                    null
                ) {
                    SimResult(false, r.elapsed, r.traceHash, r.violations + "data mismatch at $mismatch")
                } else {
                    r
                }
            }
    }
}
