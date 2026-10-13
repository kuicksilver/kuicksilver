// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.quic.wire.localTransportParameters
import io.kuicksilver.tls.TlsRole
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * The seed corpus of the fuzz targets: datagrams of a Null-crypto handshake plus hand-made inputs after
 * known QUIC CVEs. With `KUICKSILVER_FUZZ_SEEDS_OUT` set (`tools/fuzz/gen-seeds.sh`) the seeds are written to that
 * directory in Jazzer's `<Class>Inputs/<method>/` layout; otherwise the committed corpus must match the generator.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class SeedCorpusTest {
    @Test fun corpusMatchesGenerator() {
        val seeds = generate()
        val out = System.getenv("KUICKSILVER_FUZZ_SEEDS_OUT")
        if (out != null) {
            for ((path, bytes) in seeds) {
                File(out, path).apply {
                    parentFile.mkdirs()
                    writeBytes(bytes)
                }
            }
            return
        }
        assertTrue(seeds.size > 40)
        for ((path, bytes) in seeds) {
            val committed = javaClass.getResourceAsStream(path)?.use { it.readBytes() }
            assertNotNull(committed, "seed $path is missing: run tools/fuzz/gen-seeds.sh")
            assertContentEquals(bytes, committed, "seed $path is stale: run tools/fuzz/gen-seeds.sh")
        }
        assertContentEquals(
            generate().values.flatMap { it.toList() },
            seeds.values.flatMap { it.toList() },
            "the generator is not deterministic",
        )
    }

    // ---- wire helpers ----
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private fun varint8(v: Long) =
        ByteArray(8) { ((v ushr (8 * (7 - it))) and 0xff).toByte() }.also {
            it[0] =
                (it[0].toInt() or 0xc0).toByte()
        }

    private fun varint(v: Long): ByteArray =
        when {
            v < 64 -> bytes(v.toInt())
            v < 16384 -> bytes(0x40 or (v ushr 8).toInt(), (v and 0xff).toInt())
            else -> varint8(v)
        }

    private fun cat(vararg parts: ByteArray): ByteArray = ByteArrayOutputStream().also { o -> parts.forEach { o.write(it) } }.toByteArray()

    private val maxOffset = (1L shl 62) - 1

    private fun retireX1000() = cat(*Array(1000) { cat(bytes(0x19), varint(it.toLong())) })

    private fun cryptoMaxOffset() = cat(bytes(0x06), varint8(maxOffset), bytes(0x01, 0x00))

    private fun unknownFrame() = bytes(0x21)

    private fun truncatedVarint() = bytes(0x10, 0x80, 0x00)

    private fun duplicateTp() = bytes(0x04, 0x01, 0x10, 0x04, 0x01, 0x10)

    /** [initial] with a Retry token (RFC 9000 section 17.2.2). */
    private fun initialWithToken(
        payload: ByteArray,
        token: ByteArray,
    ): ByteArray {
        val dcid = ByteArray(8) { (0x11 + it).toByte() }
        val scid = ByteArray(8) { (0x21 + it).toByte() }
        val head = cat(bytes(0xc0, 0, 0, 0, 1, 8), dcid, bytes(8), scid, varint(token.size.toLong()), token)
        val body = payload.copyOf(maxOf(payload.size, 1200 - head.size - 2 - 1 - 16))
        val length = 1 + body.size + 16
        return cat(head, bytes(0x40 or (length ushr 8), length and 0xff), bytes(0), body, ByteArray(16))
    }

    private class Retry(
        val scid: ByteArray,
        val token: ByteArray,
    )

    /** The Retry an `AlwaysRetry` endpoint answers to the client's first Initial: its SCID and token. */
    private fun retryCapture(): Retry {
        CoreDriver().use { d ->
            val ep =
                EndpointCore(
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto =
                                NullCryptoProvider
                            admission = ConnectionAdmission.AlwaysRetry
                        }.build(),
                    Random(5),
                )
            val c = d.client()
            for (dg in d.service(c)) d.deliver(ep, dg, fuzzClientAddr)
            val batch = PacketBatch(4)
            val n = ep.pollStateless(batch)
            check(n >= 1) { "no Retry from the AlwaysRetry endpoint" }
            val r = batch.buffer(0).toByteArray(batch.length(0))
            batch.close()
            ep.close()
            val dcidLen = r[5].toInt()
            val scidLen = r[6 + dcidLen].toInt()
            val scid = r.copyOfRange(7 + dcidLen, 7 + dcidLen + scidLen)
            return Retry(scid, r.copyOfRange(7 + dcidLen + scidLen, r.size - 16))
        }
    }

    /** A client Initial built from scratch (Null protection: identity header protection, zero tag), padded to 1200 bytes. */
    private fun initial(payload: ByteArray): ByteArray {
        val dcid = ByteArray(8) { (0x11 + it).toByte() }
        val scid = ByteArray(8) { (0x21 + it).toByte() }
        val head = cat(bytes(0xc0, 0, 0, 0, 1, 8), dcid, bytes(8), scid, bytes(0))
        val body = payload.copyOf(maxOf(payload.size, 1200 - head.size - 2 - 1 - 16)) // PADDING after the frames
        val length = 1 + body.size + 16
        return cat(head, bytes(0x40 or (length ushr 8), length and 0xff), bytes(0), body, ByteArray(16))
    }

    /** ClientHello' of NullTlsSession: [type 1][u24 length][u16 alpn list][u16 tp length][tp]. */
    private fun clientHello(tp: ByteArray): ByteArray {
        val alpn = "hq-interop".encodeToByteArray()
        val list = cat(bytes(alpn.size), alpn)
        val body = cat(bytes(list.size ushr 8, list.size and 0xff), list, bytes(tp.size ushr 8, tp.size and 0xff), tp)
        return cat(bytes(1, 0, body.size ushr 8, body.size and 0xff), body)
    }

    private fun crypto(data: ByteArray) = cat(bytes(0x06, 0x00), varint(data.size.toLong()), data)

    /** A 1-RTT packet with the header of [template] (a captured short-header datagram), a later packet number and [payload]. */
    private fun oneRtt(
        template: ByteArray,
        payload: ByteArray,
        pnStep: Int,
    ): ByteArray {
        val pnLen = (template[0].toInt() and 3) + 1
        val pnOff = 1 + 8
        val head = template.copyOf(pnOff + pnLen)
        var pn = 0L
        for (i in 0 until pnLen) pn = (pn shl 8) or (head[pnOff + i].toLong() and 0xff)
        pn += pnStep
        for (i in pnLen - 1 downTo 0) {
            head[pnOff + i] = (pn and 0xff).toByte()
            pn = pn ushr 8
        }
        return cat(head, payload, ByteArray(16))
    }

    /** Packet payloads of a captured datagram (Null protection), each with its frameDecode type selector. */
    private fun payloads(datagram: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        val hv = PacketHeaderView()
        val b = PacketBuffer.of(datagram)
        try {
            var off = 0
            while (off < datagram.size && PacketHeaderCodec.parse(b, off, datagram.size, 8, hv)) {
                val type = hv.type ?: break
                val selector =
                    when (type) {
                        PacketType.Initial -> 0
                        PacketType.ZeroRtt -> 1
                        PacketType.Handshake -> 2
                        PacketType.OneRtt -> 3
                        PacketType.Retry -> break
                    }
                val start = hv.pnOffset + (datagram[off].toInt() and 3) + 1
                val end = hv.packetEnd - 16
                if (end > start) out += cat(bytes(selector), datagram.copyOfRange(start, end))
                off = hv.packetEnd
            }
        } finally {
            b.close()
        }
        return out
    }

    // ---- captures ----
    private class Handshake(
        val clientToServer: List<ByteArray>,
        val serverToClient: List<ByteArray>,
    )

    /** Client of [CoreDriver.client] against a server [io.kuicksilver.quic.EndpointCore], exactly as the targets build them. */
    private fun endpointHandshake(): Handshake {
        val c2s = ArrayList<ByteArray>()
        val s2c = ArrayList<ByteArray>()
        CoreDriver().use { d ->
            val ep = d.serverEndpoint()
            val c = d.client()
            var extra = 3
            var stream = -1L
            var rounds = 0
            while (extra > 0 && rounds++ < 200) {
                for (dg in d.service(c)) {
                    c2s += dg
                    d.deliver(ep, dg, fuzzClientAddr)
                }
                while (ep.nextAccepted() != null) { /* accept */ }
                for (s in ep.connections().toList()) {
                    for (dg in d.service(s)) {
                        s2c += dg
                        d.deliver(c, dg, fuzzServerAddr)
                    }
                }
                if (c.state == ConnectionState.Confirmed) {
                    if (stream < 0) {
                        stream = c.openStream(true)
                        c.writeStream(stream, ByteArray(100) { it.toByte() }, 0, 100, true)
                    }
                    extra--
                }
                d.tick(5)
            }
        }
        check(c2s.size >= 3 && s2c.size >= 2) { "handshake capture too short" }
        return Handshake(c2s, s2c)
    }

    /** Traffic of [CorePair] after its handshake: a request stream from the client, a response from the server. */
    private fun pairTraffic(): Handshake {
        val c2s = ArrayList<ByteArray>()
        val s2c = ArrayList<ByteArray>()
        val p = CorePair()
        try {
            check(p.handshake())
            p.filterToServer = { _, b ->
                c2s += b
                true
            }
            p.filterToClient = { _, b ->
                s2c += b
                true
            }
            val id = p.client.openStream(true)
            p.client.writeStream(id, ByteArray(300) { it.toByte() }, 0, 300, true)
            repeat(4) {
                p.step()
                p.advance(5.milliseconds)
            }
            val server: ConnectionCore = p.server!!
            val sid = server.openStream(false)
            server.writeStream(sid, ByteArray(200) { (it * 3).toByte() }, 0, 200, true)
            repeat(4) {
                p.step()
                p.advance(5.milliseconds)
            }
        } finally {
            p.close()
        }
        check(c2s.isNotEmpty() && s2c.isNotEmpty()) { "post-handshake capture empty" }
        return Handshake(c2s, s2c)
    }

    private fun generate(): Map<String, ByteArray> {
        val seeds = LinkedHashMap<String, ByteArray>()

        fun put(
            cls: String,
            method: String,
            name: String,
            data: ByteArray,
        ) {
            seeds["${cls}Inputs/$method/seed-$name"] = data
        }
        val hs = endpointHandshake()
        val post = pairTraffic()

        // frameDecode: [type selector][payload]
        put("FrameDecodeFuzzTest", "frameDecode", "unknown-frame", cat(bytes(3), unknownFrame()))
        put("FrameDecodeFuzzTest", "frameDecode", "unknown-frame-2byte", bytes(3, 0x40, 0x40))
        put("FrameDecodeFuzzTest", "frameDecode", "truncated-varint", cat(bytes(3), truncatedVarint()))
        put("FrameDecodeFuzzTest", "frameDecode", "retire-cid-x1000", cat(bytes(3), retireX1000()))
        put("FrameDecodeFuzzTest", "frameDecode", "empty-payload", bytes(3))
        put("FrameDecodeFuzzTest", "frameDecode", "crypto-max-offset", cat(bytes(0), cryptoMaxOffset()))
        put("FrameDecodeFuzzTest", "frameDecode", "stream-max-offset", cat(bytes(3, 0x0e, 0x00), varint8(maxOffset), bytes(0x01, 0x41)))
        put(
            "FrameDecodeFuzzTest",
            "frameDecode",
            "ack-many-ranges",
            cat(bytes(3, 0x02), varint(1000), bytes(0, 30, 0), *Array(30) { bytes(0, 0) }),
        )
        put(
            "FrameDecodeFuzzTest",
            "frameDecode",
            "new-connection-id",
            cat(
                bytes(3, 0x18, 0x05, 0x02, 0x08),
                ByteArray(8) {
                    7
                },
                ByteArray(16) { 9 },
            ),
        )
        put("FrameDecodeFuzzTest", "frameDecode", "connection-close", cat(bytes(3, 0x1c, 0x0a, 0x06, 0x03), "bad".encodeToByteArray()))
        (hs.clientToServer + hs.serverToClient + post.clientToServer + post.serverToClient)
            .flatMap {
                payloads(
                    it,
                )
            }.distinctBy { it.toList() }
            .forEachIndexed { i, p -> put("FrameDecodeFuzzTest", "frameDecode", "handshake-%02d".format(i), p) }

        // transportParameters: [sender selector: 0 client, 1 server][parameters]
        val cfg = QuicConfig.Default
        val clientTp =
            TransportParametersCodec.encode(
                cfg.localTransportParameters(
                    TlsRole.Client,
                    ConnectionId(
                        ByteArray(8) {
                            1
                        },
                    ),
                    null,
                ),
                TlsRole.Client,
                27,
            )
        val serverTp =
            TransportParametersCodec.encode(
                cfg.localTransportParameters(
                    TlsRole.Server,
                    ConnectionId(
                        ByteArray(8) {
                            2
                        },
                    ),
                    ConnectionId(ByteArray(8) { 3 }),
                ),
                TlsRole.Server,
                27,
            )
        put("TransportParametersFuzzTest", "transportParameters", "client-default", cat(bytes(0), clientTp))
        put("TransportParametersFuzzTest", "transportParameters", "server-default", cat(bytes(1), serverTp))
        put("TransportParametersFuzzTest", "transportParameters", "duplicate-parameter", cat(bytes(0), duplicateTp()))
        put("TransportParametersFuzzTest", "transportParameters", "truncated-varint", bytes(0, 0x04, 0x02, 0x80))
        put("TransportParametersFuzzTest", "transportParameters", "server-only-from-client", cat(bytes(0, 0x00, 0x08), ByteArray(8)))
        put(
            "TransportParametersFuzzTest",
            "transportParameters",
            "version-information",
            bytes(1, 0x11, 0x0c, 0, 0, 0, 1, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf),
        )
        put("TransportParametersFuzzTest", "transportParameters", "preferred-address", cat(bytes(1, 0x0d, 41), ByteArray(41)))

        // packetHeader: [short-header DCID length][datagram]
        put("PacketHeaderFuzzTest", "packetHeader", "empty-datagram", bytes(8))
        put(
            "PacketHeaderFuzzTest",
            "packetHeader",
            "version-negotiation",
            cat(bytes(8, 0x80, 0, 0, 0, 0, 8), ByteArray(8), bytes(8), ByteArray(8), bytes(0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf)),
        )
        put(
            "PacketHeaderFuzzTest",
            "packetHeader",
            "retry",
            cat(
                bytes(
                    8,
                    0xf0,
                    0,
                    0,
                    0,
                    1,
                    8,
                ),
                ByteArray(8),
                bytes(8),
                ByteArray(8),
                ByteArray(8) {
                    5
                },
                ByteArray(16),
            ),
        )
        put(
            "PacketHeaderFuzzTest",
            "packetHeader",
            "length-beyond-datagram",
            cat(bytes(8, 0xc0, 0, 0, 0, 1, 8), ByteArray(8), bytes(0, 0, 0x7f, 0xff, 0)),
        )
        (hs.clientToServer + hs.serverToClient + post.clientToServer.take(2)).forEachIndexed {
            i,
            dg,
            ->
            put("PacketHeaderFuzzTest", "packetHeader", "handshake-%02d".format(i), cat(bytes(8), dg))
        }

        // streamReassembler: insert [0][u16 offset + 256][u16 length][pad], read [2][max / 16], clear [3][0]
        fun ins(
            off: Int,
            len: Int,
        ) = bytes(0, (off + 256) ushr 8, (off + 256) and 0xff, len ushr 8, len and 0xff, 3)
        put("ReassemblerFuzzTest", "streamReassembler", "in-order", cat(ins(0, 100), ins(100, 100), bytes(2, 255)))
        put(
            "ReassemblerFuzzTest",
            "streamReassembler",
            "gaps-to-limit",
            cat(ins(1000, 10), ins(800, 10), ins(600, 10), ins(400, 10), ins(200, 10), ins(0, 200), bytes(2, 100)),
        )
        put(
            "ReassemblerFuzzTest",
            "streamReassembler",
            "overlap-and-clear",
            cat(ins(50, 100), ins(0, 120), ins(140, 60), bytes(2, 4), bytes(3, 0), ins(0, 10), bytes(2, 1)),
        )

        // bbrInvariants: [u16 seed][u8 datagram size / 256], then [u8 op][3-byte arguments] (BbrDriver: 0 send, 1 ack, 2 time,
        // 3 app-limited, 4 MTU, 5 timeout loss, 6 settle, 7 CE, 8 probe, 9 discard)
        fun a(v: Int) = bytes(v ushr 16, v ushr 8, v)

        fun send(n: Int) = cat(bytes(0), a(n - 1))

        fun time(
            scale: Int,
            v: Int,
        ) = cat(bytes(2), a(scale), a(v))

        fun ackOp(
            skip: Int,
            count: Int,
            flags: Int,
        ) = cat(bytes(1), a(skip), a(count - 1), a(flags))
        val bulk = cat(*Array(300) { cat(send(32), time(1, 2000), ackOp(0, 16, 0), time(1, 1000), ackOp(0, 16, 0)) })
        put("BbrInvariantFuzzTest", "bbrInvariants", "bulk", cat(bytes(0, 7, 0), bulk))
        put(
            "BbrInvariantFuzzTest",
            "bbrInvariants",
            "loss-reorder-ce",
            cat(
                bytes(0, 9, 0),
                bulk,
                *Array(200) {
                    cat(
                        send(24),
                        time(1, 3000),
                        ackOp(3, 12, if (it % 3 == 0) 0x30 else 0x01),
                        bytes(5),
                        a(2),
                        a(if (it % 50 == 0) 0 else 1),
                        bytes(6),
                        a(1),
                        bytes(7),
                    )
                },
            ),
        )
        put(
            "BbrInvariantFuzzTest",
            "bbrInvariants",
            "idle-mtu-probe",
            cat(
                bytes(0, 5, 0),
                bulk,
                bytes(3),
                time(3, 0xffff),
                bytes(4),
                a(252),
                bytes(8),
                a(3),
                send(10),
                time(0, 0),
                ackOp(0, 5, 0),
                bytes(9),
                a(4),
                bulk,
            ),
        )

        // packetRecvServer: one client datagram to a fresh server endpoint
        put("PacketReceiveFuzzTest", "packetRecvServer", "empty-datagram", ByteArray(0))
        put("PacketReceiveFuzzTest", "packetRecvServer", "handshake-initial", hs.clientToServer[0])
        put("PacketReceiveFuzzTest", "packetRecvServer", "initial-duplicate-tp", initial(crypto(clientHello(cat(clientTp, duplicateTp())))))
        put(
            "PacketReceiveFuzzTest",
            "packetRecvServer",
            "initial-unknown-frame",
            initial(cat(crypto(clientHello(clientTp)), unknownFrame())),
        )
        put(
            "PacketReceiveFuzzTest",
            "packetRecvServer",
            "initial-truncated-varint",
            initial(cat(crypto(clientHello(clientTp)), bytes(0x02, 0x80))),
        )
        put("PacketReceiveFuzzTest", "packetRecvServer", "initial-crypto-max-offset", initial(cryptoMaxOffset()))
        put("PacketReceiveFuzzTest", "packetRecvServer", "initial-retire-cid-x1000", initial(retireX1000()))
        put(
            "PacketReceiveFuzzTest",
            "packetRecvServer",
            "initial-truncated-client-hello",
            initial(
                crypto(
                    clientHello(clientTp).copyOf(20).also {
                        it[3] =
                            16
                    },
                ),
            ),
        )
        put(
            "PacketReceiveFuzzTest",
            "packetRecvServer",
            "unknown-version",
            hs.clientToServer[0].copyOf().also {
                it[1] = 0x0a
                it[2] = 0x0a
                it[3] =
                    0x0a
                it[4] = 0x0a
            },
        )

        // packetRecvClient: one server datagram to a client that sent its first Initial
        put("PacketReceiveFuzzTest", "packetRecvClient", "empty-datagram", ByteArray(0))
        hs.serverToClient.forEachIndexed { i, dg -> put("PacketReceiveFuzzTest", "packetRecvClient", "handshake-%02d".format(i), dg) }

        // multiPacket: length-prefixed client datagrams to one server endpoint
        put("PacketReceiveFuzzTest", "multiPacket", "handshake", Framing.join(hs.clientToServer))
        put(
            "PacketReceiveFuzzTest",
            "multiPacket",
            "empty-datagrams",
            Framing.join(listOf(ByteArray(0), ByteArray(0), hs.clientToServer[0], ByteArray(0))),
        )
        put(
            "PacketReceiveFuzzTest",
            "multiPacket",
            "initial-then-duplicate-tp",
            Framing.join(listOf(hs.clientToServer[0], initial(crypto(clientHello(cat(clientTp, duplicateTp())))))),
        )
        put("PacketReceiveFuzzTest", "multiPacket", "initial-repeated", Framing.join(List(4) { hs.clientToServer[0] }))

        // retryPacket: [flags][scid length][scid][token]: the token of a real Retry, a corrupt tag, an empty token, a v2 Retry
        val retry = retryCapture()
        put("RetryPacketFuzzTest", "retryPacket", "real-token", cat(bytes(0, retry.scid.size), retry.scid, retry.token))
        put("RetryPacketFuzzTest", "retryPacket", "corrupt-tag", cat(bytes(1, retry.scid.size), retry.scid, retry.token))
        put("RetryPacketFuzzTest", "retryPacket", "empty-token", bytes(0, 8, 1, 2, 3, 4, 5, 6, 7, 8))
        put("RetryPacketFuzzTest", "retryPacket", "v2", cat(bytes(2, retry.scid.size), retry.scid, retry.token))
        put("RetryPacketFuzzTest", "retryPacket", "scid-equals-odcid", cat(bytes(0, 8), ByteArray(8) { (0x11 + it).toByte() }, retry.token))

        // endpointRoute: [bit 0: stranger][length-prefixed datagrams] to an endpoint holding one established connection
        val serverCid =
            ByteArray(8) { (it * 17 + 1).toByte() }.also {
                it[0] = 0x01
                it[1] = 0
            }

        fun shortTo(
            dcid: ByteArray,
            size: Int,
        ): ByteArray {
            val b = ByteArray(size) { (it * 31).toByte() }
            b[0] = 0x40
            dcid.copyInto(b, 1)
            return b
        }
        put("EndpointRouteFuzzTest", "endpointRoute", "client-traffic", cat(bytes(0), Framing.join(post.clientToServer)))
        put("EndpointRouteFuzzTest", "endpointRoute", "reset-candidate", cat(bytes(0), Framing.join(listOf(shortTo(serverCid, 100)))))
        put(
            "EndpointRouteFuzzTest",
            "endpointRoute",
            "reset-candidate-stranger",
            cat(
                bytes(
                    1,
                ),
                Framing.join(
                    listOf(
                        shortTo(serverCid, 100),
                        shortTo(
                            ByteArray(8) {
                                9
                            },
                            60,
                        ),
                    ),
                ),
            ),
        )
        put(
            "EndpointRouteFuzzTest",
            "endpointRoute",
            "initial-with-token",
            cat(bytes(1), Framing.join(listOf(initialWithToken(crypto(clientHello(clientTp)), retry.token)))),
        )
        put("EndpointRouteFuzzTest", "endpointRoute", "initial-repeated", cat(bytes(1), Framing.join(List(3) { hs.clientToServer[0] })))
        put(
            "EndpointRouteFuzzTest",
            "endpointRoute",
            "version-negotiation-to-server",
            cat(bytes(0), Framing.join(listOf(cat(bytes(0x80, 0, 0, 0, 0, 8), serverCid, bytes(8), ByteArray(8), bytes(0, 0, 0, 1))))),
        )

        // postHandshake: [flags][length-prefixed datagrams]; bit 0: to the client, bit 1: key update first, bit 2: PATH_CHALLENGEs, bit 3: DATAGRAMs
        put("PacketReceiveFuzzTest", "postHandshake", "key-update-then-client-traffic", cat(bytes(2), Framing.join(post.clientToServer)))
        put(
            "PacketReceiveFuzzTest",
            "postHandshake",
            "path-challenges-and-datagrams",
            cat(bytes(12), Framing.join(post.serverToClient.take(1))),
        )
        val c1 = post.clientToServer.first()
        val s1 = post.serverToClient.first()
        put("PacketReceiveFuzzTest", "postHandshake", "client-traffic", cat(bytes(0), Framing.join(post.clientToServer)))
        put("PacketReceiveFuzzTest", "postHandshake", "server-traffic", cat(bytes(1), Framing.join(post.serverToClient)))
        put("PacketReceiveFuzzTest", "postHandshake", "empty-datagram", cat(bytes(0), Framing.join(listOf(ByteArray(0)))))
        put(
            "PacketReceiveFuzzTest",
            "postHandshake",
            "retire-cid-x1000",
            cat(bytes(0), Framing.join(listOf(oneRtt(c1, retireX1000(), 50)))),
        )
        put(
            "PacketReceiveFuzzTest",
            "postHandshake",
            "retire-cid-x1000-to-client",
            cat(bytes(1), Framing.join(listOf(oneRtt(s1, retireX1000(), 50)))),
        )
        put(
            "PacketReceiveFuzzTest",
            "postHandshake",
            "crypto-max-offset",
            cat(bytes(0), Framing.join(listOf(oneRtt(c1, cryptoMaxOffset(), 50)))),
        )
        put(
            "PacketReceiveFuzzTest",
            "postHandshake",
            "unknown-frame",
            cat(bytes(0), Framing.join(listOf(oneRtt(c1, cat(bytes(0x01), unknownFrame()), 50)))),
        )
        put(
            "PacketReceiveFuzzTest",
            "postHandshake",
            "truncated-varint",
            cat(bytes(1), Framing.join(listOf(oneRtt(s1, truncatedVarint(), 50)))),
        )
        put(
            "PacketReceiveFuzzTest",
            "postHandshake",
            "stream-max-offset",
            cat(bytes(0), Framing.join(listOf(oneRtt(c1, cat(bytes(0x0e, 0x00), varint8(maxOffset), bytes(0x01, 0x41)), 50)))),
        )
        connectionSeeds(::put)
        zeroRttSeeds(::put, serverTp)
        return seeds
    }

    /** Programs of the stateful connection fuzzer ([ConnProgram]); connectionNull and connectionTls share them. */
    private fun connectionSeeds(put: (String, String, String, ByteArray) -> Unit) {
        val programs = LinkedHashMap<String, ByteArray>()
        val kinds = ConnProgram.FRAME_KINDS
        // every frame kind, sealed by either side into 1-RTT packets after the handshake, with typical field values
        val fields =
            mapOf(
                "PADDING" to longArrayOf(3),
                "PING" to longArrayOf(),
                "ACK" to longArrayOf(3, 10, 1, 0, 0, 1),
                "ACK_ECN" to longArrayOf(3, 10, 0, 2, 3, 0, 1),
                "RESET_STREAM" to longArrayOf(0, 7, 100),
                "STOP_SENDING" to longArrayOf(0, 7),
                "CRYPTO" to longArrayOf(0, 20),
                "NEW_TOKEN" to longArrayOf(16),
                "MAX_DATA" to longArrayOf(1_000_000),
                "MAX_STREAM_DATA" to longArrayOf(0, 100_000),
                "MAX_STREAMS_BIDI" to longArrayOf(200),
                "MAX_STREAMS_UNI" to longArrayOf(200),
                "DATA_BLOCKED" to longArrayOf(1000),
                "STREAM_DATA_BLOCKED" to longArrayOf(0, 1000),
                "STREAMS_BLOCKED_BIDI" to longArrayOf(10),
                "STREAMS_BLOCKED_UNI" to longArrayOf(10),
                "RETIRE_CONNECTION_ID" to longArrayOf(1),
                "CONNECTION_CLOSE" to longArrayOf(10, 6, 4),
                "CONNECTION_CLOSE_APP" to longArrayOf(1, 3),
                "HANDSHAKE_DONE" to longArrayOf(),
                "DATAGRAM" to longArrayOf(50),
                "DATAGRAM_LEN" to longArrayOf(50),
                "UNKNOWN" to longArrayOf(0x21, 4),
            )
        for (kind in kinds) {
            for (side in 0..1) {
                val b = ConnProgram.Builder(0).app(0, 0, ConnProgram.num(300), byteArrayOf(0))
                b.steps(2)
                val k = kinds.indexOf(kind)
                when (kind) {
                    "STREAM" -> {
                        b.frameRaw(
                            side,
                            3,
                            k,
                            byteArrayOf(0x07),
                            ConnProgram.num(side.toLong()),
                            ConnProgram.num(0),
                            ConnProgram.num(100),
                        )
                    }

                    "NEW_CONNECTION_ID" -> {
                        b.frameRaw(side, 3, k, ConnProgram.num(4), ConnProgram.num(0), byteArrayOf(8, 0x33))
                    }

                    "PATH_CHALLENGE", "PATH_RESPONSE" -> {
                        b.frameRaw(side, 3, k, byteArrayOf(0x44))
                    }

                    else -> {
                        b.frame(side, 3, kind, *fields.getValue(kind))
                    }
                }
                programs["frame-${kind.lowercase()}-${if (side == 0) "to-server" else "to-client"}"] = b.steps(4).build()
            }
        }
        // a STREAM frame: [selector][bits OFF|LEN|FIN][id][offset][length]; NEW_CONNECTION_ID: [seq][retire][len][seed]
        programs["stream-frames"] =
            ConnProgram
                .Builder(0)
                .frameRaw(0, 3, kinds.indexOf("STREAM"), byteArrayOf(0x07), ConnProgram.num(0), ConnProgram.num(0), ConnProgram.num(100))
                .frameRaw(0, 3, kinds.indexOf("STREAM"), byteArrayOf(0x06), ConnProgram.num(0), ConnProgram.num(100), ConnProgram.num(50))
                .frameRaw(1, 3, kinds.indexOf("STREAM"), byteArrayOf(0x02), ConnProgram.num(1), ConnProgram.num(200))
                .steps(4)
                .build()
        programs["new-connection-ids"] =
            ConnProgram
                .Builder(0)
                .frameRaw(1, 3, kinds.indexOf("NEW_CONNECTION_ID"), ConnProgram.num(2), ConnProgram.num(0), byteArrayOf(8, 0x40))
                .frameRaw(1, 3, kinds.indexOf("NEW_CONNECTION_ID"), ConnProgram.num(3), ConnProgram.num(2), byteArrayOf(8, 0x50))
                .frame(1, 3, "RETIRE_CONNECTION_ID", 1)
                .frameRaw(0, 3, kinds.indexOf("NEW_CONNECTION_ID"), ConnProgram.num(9), ConnProgram.num(8), byteArrayOf(20, 0x60))
                .steps(6)
                .build()
        programs["path-challenge-response"] =
            ConnProgram
                .Builder(0)
                .frameRaw(0, 3, kinds.indexOf("PATH_CHALLENGE"), byteArrayOf(0x11))
                .frameRaw(1, 3, kinds.indexOf("PATH_RESPONSE"), byteArrayOf(0x22))
                .steps(3)
                .build()
        // application traffic both ways with resets, STOP_SENDING, reads, datagrams, a key update
        programs["streams-and-resets"] =
            ConnProgram
                .Builder(0)
                .app(0, 0, ConnProgram.num(5000), byteArrayOf(0))
                .app(0, 0, ConnProgram.num(2000), byteArrayOf(1), uni = true)
                .steps(3)
                .app(1, 2, byteArrayOf(0), ConnProgram.num(4000))
                .app(1, 1, byteArrayOf(0), ConnProgram.num(3000))
                .steps(3)
                .app(0, 3, byteArrayOf(0), ConnProgram.num(9))
                .app(1, 4, byteArrayOf(1), ConnProgram.num(8))
                .app(0, 6, ConnProgram.num(200))
                .app(1, 6, ConnProgram.num(300))
                .steps(3)
                .step(readDatagrams = true)
                .app(0, 5)
                .steps(4)
                .app(1, 7, ConnProgram.num(0))
                .steps(3)
                .build()
        // small limits: windows and stream counts are reachable
        programs["small-limits"] =
            ConnProgram
                .Builder(2)
                .app(0, 0, ConnProgram.num(3000), byteArrayOf(0))
                .app(0, 0, ConnProgram.num(3000), byteArrayOf(0))
                .steps(3)
                .app(1, 2, byteArrayOf(0), ConnProgram.num(3000))
                .steps(2)
                .frame(0, 3, "MAX_STREAMS_BIDI", 6)
                .frame(0, 3, "MAX_STREAM_DATA", 1, 100)
                .frame(1, 3, "MAX_DATA", 100)
                .steps(4)
                .build()
        // network effects: loss, duplication, reordering, ECN marks, a NAT rebinding, timers
        programs["network"] =
            ConnProgram
                .Builder(4)
                .app(0, 0, ConnProgram.num(4000), byteArrayOf(1))
                .step()
                .net(0, 0)
                .net(1, 1)
                .net(0, 2)
                .net(0, 3)
                .net(1, 7)
                .step()
                .net(0, 8)
                .steps(3)
                .tick(3)
                .tick(15)
                .steps(2)
                .build()
        // frames of every level while the handshake runs (Initial, Handshake, 0-RTT injection points)
        programs["handshake-levels"] =
            ConnProgram
                .Builder(1)
                .frame(0, 0, "PING")
                .frame(0, 0, "ACK", 0, 0, 0, 0)
                .step()
                .frame(1, 0, "CRYPTO", 1000, 10)
                .frame(1, 2, "PING")
                .steps(2)
                .frame(0, 2, "ACK", 1, 0, 0, 1)
                .frame(1, 3, "HANDSHAKE_DONE")
                .steps(6)
                .build()
        programs["raw-1rtt"] =
            ConnProgram
                .Builder(0)
                .raw(0, 3, byteArrayOf(0x01, 0x00, 0x00, 0x1e))
                .raw(1, 3, byteArrayOf(0x07, 0x04, 1, 2, 3, 4))
                .steps(3)
                .build()
        for ((name, program) in programs) {
            put("ConnectionFuzzTest", "connectionNull", name, program)
            put("ConnectionFuzzTest", "connectionTls", name, program)
        }
    }

    private fun zeroRttSeeds(
        put: (String, String, String, ByteArray) -> Unit,
        serverTp: ByteArray,
    ) {
        // replayRegister: [layout][op][args] (see ZeroRttFuzzTest.replayRegister); layouts 0..3 from tiny to the production one
        for (layout in 0..3) {
            put("ZeroRttFuzzTest", "replayRegister", "replay-$layout", bytes(layout, 0, 1, 0, 1, 2, 0x13, 0x88, 0, 1, 2, 0x4e, 0x20, 0, 1))
            put("ZeroRttFuzzTest", "replayRegister", "release-then-admit-$layout", bytes(layout, 0, 5, 1, 5, 0, 5, 0, 5))
            put(
                "ZeroRttFuzzTest",
                "replayRegister",
                "wall-clock-steps-$layout",
                bytes(layout, 0, 2, 2, 0x61, 0xa8, 3, 0xf6, 0x3c, 0, 2, 2, 0x4e, 0x20, 0, 2),
            )
            put("ZeroRttFuzzTest", "replayRegister", "fill-$layout", bytes(layout, 4, 0x01, 0x00, 0, 3, 4, 0x01, 0x00, 2, 0x75, 0x30, 0, 3))
        }
        put("ZeroRttFuzzTest", "replayRegister", "explicit-id", cat(bytes(1, 5), ByteArray(32) { 1 }, bytes(5), ByteArray(32) { 1 }))
        // rememberedTicket: [flags][blob] or [flags][alpn length][alpn][tp]
        val h3 = "h3".encodeToByteArray()
        put("ZeroRttFuzzTest", "rememberedTicket", "h3-server-tp", cat(bytes(0, h3.size), h3, serverTp))
        put("ZeroRttFuzzTest", "rememberedTicket", "blob", cat(bytes(1, h3.size), h3, serverTp))
        put("ZeroRttFuzzTest", "rememberedTicket", "empty-alpn", cat(bytes(1, 0), serverTp))
    }
}
