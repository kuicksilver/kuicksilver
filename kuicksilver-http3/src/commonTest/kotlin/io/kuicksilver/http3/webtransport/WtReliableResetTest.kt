// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportReceiveStream
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The Reliable Size of every RESET_STREAM_AT the client's qlog shows it sent. */
private class SentReliableSizes : QlogSink {
    /** Written on the endpoint loop only, read by the test. */
    @kotlin.concurrent.Volatile var sizes: List<Long> = emptyList()

    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace? =
        if (role != TlsRole.Client) {
            null
        } else {
            object : QlogTrace {
                override fun write(record: String) {
                    if ("packet_sent" !in record) return
                    sizes = sizes +
                        Regex("\"frame_type\":\"reset_stream_at\"[^}]*\"reliable_size\":(\\d+)").findAll(record).map {
                            it.groupValues[1].toLong()
                        }
                }

                override fun close() {}
            }
        }
}

/** The bytes [s] delivers before its reset, and the reset's application code. */
private suspend fun prefixAndReset(s: WebTransportReceiveStream): Pair<ByteArray, Long?> {
    var got = ByteArray(0)
    val buf = ByteArray(1024)
    val e =
        assertFailsWith<Throwable> {
            withTimeout(10.seconds) {
                while (true) {
                    val n = s.input.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    got += buf.copyOf(n)
                }
            }
        }
    val reset = generateSequence(e) { it.cause }.filterIsInstance<WebTransportException.StreamReset>().first()
    return got to reset.code
}

/**
 * draft-ietf-webtrans-http3-17 section 4.4: "WebTransport implementations MUST use the RESET_STREAM_AT frame when resetting
 * a WebTransport data stream, with a Reliable Size set to the size of the WebTransport header on that stream plus any
 * offset provided by the application"; draft-ietf-webtrans-overview section 4.3, "abort send side" with an offset.
 */
class WtReliableResetTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The first [reliableOffset] bytes reach the peer's application although every packet of the client was lost when
     * they were written, and the reset follows them; the Reliable Size is the header (3 bytes: type 0x54, a 2-byte varint, and Session ID 0)
     * plus the offset.
     */
    @Test fun theReliablePrefixReachesThePeerThroughLoss() =
        h3Test {
            val sizes = SentReliableSizes()
            H3Pair
                .open(
                    clientSettings = wtOn,
                    serverSettings = wtOn,
                    clientQuic =
                        quicConfig {
                            resetStreamAt = true
                            qlog = sizes
                        },
                ).useScoped { p ->
                    val (client, server) = sessions(p)
                    val clientAddr =
                        p.client.quic.paths
                            .first()
                            .localAddress
                    p.quic.net.drop = { from, _, _ -> from == clientAddr } // the header and the data are lost
                    val out = client.openUni()
                    out.output.writeFully("hello world".encodeToByteArray())
                    out.output.flush()
                    out.reset(5, reliableOffset = 5)
                    p.quic.net.drop = null
                    val st = withTimeout(10.seconds) { server.acceptUni() }
                    val (got, code) = prefixAndReset(st)
                    assertEquals(5L, code)
                    assertTrue(3L + 5 in sizes.sizes, "${sizes.sizes}")
                    assertContentEquals("hello".encodeToByteArray(), got.copyOf(minOf(got.size, 5)))
                    assertTrue(got.size >= 5, "${got.size} bytes before the reset")
                }
        }

    /** An offset beyond the bytes written before the call is cut to them; new writes fail at once. */
    @Test fun negative_anOffsetBeyondTheWrittenBytesIsCutToThem() =
        h3Test {
            val sizes = SentReliableSizes()
            H3Pair
                .open(
                    clientSettings = wtOn,
                    serverSettings = wtOn,
                    clientQuic =
                        quicConfig {
                            resetStreamAt = true
                            qlog = sizes
                        },
                ).useScoped { p ->
                    val (client, server) = sessions(p)
                    val out = client.openUni()
                    out.output.writeFully("abc".encodeToByteArray())
                    out.output.flush()
                    out.reset(7, reliableOffset = 1_000)
                    assertFailsWith<Throwable> {
                        out.output.writeFully("more".encodeToByteArray())
                        out.output.flush()
                    }
                    val (got, code) = prefixAndReset(withTimeout(10.seconds) { server.acceptUni() })
                    assertEquals(7L, code)
                    assertContentEquals("abc".encodeToByteArray(), got)
                    withTimeout(10.seconds) { while (sizes.sizes.isEmpty()) kotlinx.coroutines.yield() }
                    assertEquals(listOf(3L + 3), sizes.sizes.distinct())
                }
        }

    /**
     * The output was already closed and its pump ended (the FIN sent, lost here, so not acknowledged): the reset with a
     * reliable offset still goes, with the header plus the offset as its Reliable Size.
     */
    @Test fun aReliableResetAfterTheFinStillGoes() =
        h3Test {
            val sizes = SentReliableSizes()
            H3Pair
                .open(
                    clientSettings = wtOn,
                    serverSettings = wtOn,
                    clientQuic =
                        quicConfig {
                            resetStreamAt = true
                            qlog = sizes
                        },
                ).useScoped { p ->
                    val (client, server) = sessions(p)
                    val clientAddr =
                        p.client.quic.paths
                            .first()
                            .localAddress
                    p.quic.net.drop = { from, _, _ -> from == clientAddr }
                    val out = client.openUni()
                    out.output.writeFully("abc".encodeToByteArray())
                    out.output.flushAndClose()
                    withTimeout(10.seconds) { while (!(out as WtStreamImpl).outputEndedForTest) kotlinx.coroutines.yield() }
                    out.reset(7, reliableOffset = 2)
                    p.quic.net.drop = null
                    val (got, code) = prefixAndReset(withTimeout(10.seconds) { server.acceptUni() })
                    assertEquals(7L, code)
                    assertContentEquals("ab".encodeToByteArray(), got.copyOf(minOf(got.size, 2)))
                    assertTrue(3L + 2 in sizes.sizes, "${sizes.sizes}")
                }
        }

    /**
     * A reset with a reliable offset waits for the peer's flow-control credit (the server gives 2 bytes and reads nothing),
     * without a deadline; a later plain reset takes over at once, with the bytes already sent kept: Reliable Size = header
     * + 2, never the asked 8.
     */
    @Test fun negative_aLaterResetTakesOverAReliableResetWaitingForCredit() =
        h3Test {
            val sizes = SentReliableSizes()
            H3Pair
                .open(
                    clientSettings = wtOn,
                    serverSettings = wtLimits(data = 2),
                    clientQuic =
                        quicConfig {
                            resetStreamAt = true
                            qlog = sizes
                        },
                ).useScoped { p ->
                    val (client, server) = sessions(p)
                    val out = client.openUni()
                    out.output.writeFully("abcdefghij".encodeToByteArray())
                    out.output.flush()
                    out.reset(5, reliableOffset = 8)
                    val c = client as WtSessionImpl
                    withTimeout(10.seconds) {
                        while (kotlinx.coroutines.withContext(c.dispatcherForTest) { c.flow!!.sentForTest[WtFlow.DATA_BLOCKED] ?: 0 } ==
                            0
                        ) {
                            kotlinx.coroutines.yield()
                        }
                    }
                    out.reset(9)
                    val (got, code) = prefixAndReset(withTimeout(10.seconds) { server.acceptUni() })
                    assertEquals(9L, code)
                    assertContentEquals("ab".encodeToByteArray(), got)
                    withTimeout(10.seconds) { while (sizes.sizes.isEmpty()) kotlinx.coroutines.yield() }
                    assertEquals(listOf(3L + 2), sizes.sizes.distinct())
                }
        }

    /** A negative offset is refused before anything happens; the stream still writes and ends. */
    @Test fun negative_aNegativeOffsetIsRefused() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val out = client.openUni()
                assertFailsWith<IllegalArgumentException> { out.reset(1, reliableOffset = -1) }
                out.output.writeFully("ok".encodeToByteArray())
                out.output.flushAndClose()
                val st = withTimeout(10.seconds) { server.acceptUni() }
                assertContentEquals("ok".encodeToByteArray(), withTimeout(10.seconds) { st.input.readAllBytesOf() })
            }
        }

    /**
     * A draft-02 session has no RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset section 3: "An endpoint MUST NOT
     * send a RESET_STREAM_AT frame unless the peer advertised support"): an offset above 0 is refused with
     * IllegalStateException and resets nothing; offset 0 is the plain reset, RESET_STREAM.
     */
    @Test fun negative_aReliableOffsetWithoutResetStreamAtIsRefused() =
        h3Test {
            val draft02Only = setOf(SettingsId.WT_ENABLED_DRAFT17, SettingsId.WT_ENABLED_DRAFT16, SettingsId.WT_MAX_SESSIONS_DRAFT14)
            H3Session.createdForTest = { it.ourSettingsForTest = { l -> l.filter { (id, _) -> id !in draft02Only } } }
            try {
                H3Pair
                    .open(clientSettings = wtOn, serverSettings = wtOn, serverQuic = QuicConfig.Default, clientQuic = QuicConfig.Default)
                    .useScoped { p ->
                        val (client, server) = sessions(p)
                        assertEquals(WtVersion.Draft02, (client as WtSessionImpl).version)
                        val out = client.openUni()
                        out.output.writeFully("abc".encodeToByteArray())
                        out.output.flush()
                        assertFailsWith<IllegalStateException> { out.reset(3, reliableOffset = 2) }
                        out.reset(3, reliableOffset = 0)
                        val (_, code) = prefixAndReset(withTimeout(10.seconds) { server.acceptUni() })
                        assertEquals(3L, code)
                    }
            } finally {
                H3Session.createdForTest = null
            }
        }
}

private suspend fun io.ktor.utils.io.ByteReadChannel.readAllBytesOf(): ByteArray {
    var all = ByteArray(0)
    val buf = ByteArray(1024)
    while (true) {
        val n = readAvailable(buf, 0, buf.size)
        if (n < 0) return all
        all += buf.copyOf(n)
    }
}
