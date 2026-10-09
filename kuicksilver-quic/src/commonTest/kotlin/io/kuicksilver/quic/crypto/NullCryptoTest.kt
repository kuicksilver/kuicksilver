// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.crypto

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.tls.Direction
import io.kuicksilver.tls.DriveResult
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.PacketProtectionException
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

@OptIn(DelicateKuicksilverApi::class)
class NullCryptoTest {
    @Test fun nullEndpointKeysDeterministic() {
        val t = NullCryptoProvider.newTokenKey()
        val sealed = t.seal(5L, byteArrayOf(1), byteArrayOf(9, 9, 9))
        kotlin.test.assertEquals(3 + 16, sealed.size)
        kotlin.test.assertContentEquals(byteArrayOf(9, 9, 9), t.open(5L, byteArrayOf(1), sealed))
        kotlin.test.assertNull(t.open(5L, byteArrayOf(1), sealed.copyOf().also { it[4] = 1 }), "a non-zero tag never opens")
        val r1 = NullCryptoProvider.newResetKey()
        val r2 = NullCryptoProvider.newResetKey()
        val cid =
            io.kuicksilver.native.PacketBuffer
                .of(ByteArray(8) { 3 })
        try {
            val a = ByteArray(16)
            val b = ByteArray(16)
            r1.token(cid, 0, 8, a, 0)
            r2.token(cid, 0, 8, b, 0)
            kotlin.test.assertContentEquals(a, b, "deterministic across instances (simulator)")
            kotlin.test.assertTrue(
                a.any {
                    it !=
                        0.toByte()
                },
            )
        } finally {
            cid.close()
        }
    }

    private val accept =
        TrustConfig.Custom { chain, _, _ ->
            io.kuicksilver.tls.VerifyResult
                .Accepted(chain)
        }

    private fun client(alpn: List<String> = listOf("h3")) =
        tlsConfig(TlsRole.Client) {
            this.alpn = alpn
            serverName = "server.test"
            trust =
                accept
        }

    private fun server(alpn: List<String> = listOf("h3")) =
        tlsConfig(TlsRole.Server) {
            this.alpn = alpn
            identity =
                TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        }

    @Test fun nullSealAppendsSixteenZeroBytes() {
        val (_, w) = NullCryptoProvider.initialProtectors(ByteArray(8), 1, TlsRole.Client)
        val h = PacketBuffer.of(byteArrayOf(1, 2))
        val p = PacketBuffer.allocate(40)
        try {
            p.copyFrom(ByteArray(10) { 7 }, 0, 4, 10)
            assertEquals(26, w.seal(1, h, 0, 2, p, 4, 10))
            assertContentEquals(ByteArray(10) { 7 } + ByteArray(16), p.toByteArray(30).copyOfRange(4, 30))
        } finally {
            h.close()
            p.close()
            w.close()
        }
    }

    @Test fun nullOpenRejectsNonZeroTag() {
        val (r, _) = NullCryptoProvider.initialProtectors(ByteArray(8), 1, TlsRole.Server)
        val h = PacketBuffer.of(byteArrayOf(1))
        val p = PacketBuffer.allocate(40)
        try {
            assertEquals(4, r.open(1, h, 1, p, 20))
            p[19] = 1
            assertFailsWith<PacketProtectionException> { r.open(1, h, 1, p, 20) }
        } finally {
            h.close()
            p.close()
            r.close()
        }
    }

    @Test fun nullHeaderMaskIsZero() {
        val (r, _) = NullCryptoProvider.initialProtectors(ByteArray(8), 1, TlsRole.Server)
        val s = PacketBuffer.of(ByteArray(16) { 9 })
        val m = ByteArray(5) { 1 }
        try {
            r.headerMask(s, 0, m)
            assertContentEquals(ByteArray(5), m)
            assertContentEquals(ByteArray(16), NullCryptoProvider.retryIntegrityTag(1, ByteArray(8), ByteArray(3)))
        } finally {
            s.close()
            r.close()
        }
    }

    private class Side(
        val s: QuicTlsSession,
    ) {
        var done = false
        val keys = ArrayList<Pair<EncryptionLevel, Direction>>()
        var tp: ByteArray? = null
        var last: DriveResult = DriveResult.WantRead
    }

    private fun pump(
        c: QuicTlsSession,
        s: QuicTlsSession,
    ): Pair<Side, Side> {
        val cs = Side(c)
        val ss = Side(s)
        repeat(10) {
            for ((me, peer) in listOf(cs to ss, ss to cs)) {
                me.last = me.s.drive()
                while (true) {
                    when (val ev = me.s.nextEvent() ?: break) {
                        is TlsEvent.CryptoData -> {
                            peer.s.provide(ev.level, ev.data)
                        }

                        is TlsEvent.Keys -> {
                            me.keys += ev.level to ev.direction
                            ev.protector.close()
                        }

                        is TlsEvent.PeerTransportParameters -> {
                            me.tp = ev.encoded
                        }

                        TlsEvent.HandshakeDone -> {
                            me.done = true
                        }
                    }
                }
                if (me.last is DriveResult.Failed) return cs to ss
            }
        }
        return cs to ss
    }

    @Test fun nullHandshakeInMemory() {
        val c = NullCryptoProvider.newSession(client())
        val s = NullCryptoProvider.newSession(server())
        try {
            c.setTransportParameters(byteArrayOf(1, 2, 3))
            s.setTransportParameters(byteArrayOf(4, 5))
            val (cs, ss) = pump(c, s)
            assertTrue(cs.done && ss.done)
            for (side in listOf(cs, ss)) {
                assertEquals(2, side.keys.count { it.first == EncryptionLevel.Handshake })
                assertEquals(
                    2,
                    side.keys.count {
                        it.first ==
                            EncryptionLevel.Application
                    },
                )
            }
            assertContentEquals(byteArrayOf(4, 5), cs.tp)
            assertContentEquals(byteArrayOf(1, 2, 3), ss.tp)
            assertIs<DriveResult.WantRead>(c.drive()) // stable after completion
        } finally {
            c.close()
            s.close()
        }
    }

    @Test fun nullAlpnMismatchFailsWithAlert120() {
        val c = NullCryptoProvider.newSession(client(listOf("h3")))
        val s = NullCryptoProvider.newSession(server(listOf("hq-interop")))
        try {
            c.setTransportParameters(ByteArray(0))
            s.setTransportParameters(ByteArray(0))
            val (_, ss) = pump(c, s)
            val f = assertIs<DriveResult.Failed>(ss.last)
            assertEquals(120, f.alert)
            assertIs<TlsException.Protocol>(f.exception)
        } finally {
            c.close()
            s.close()
        }
    }

    /** Fuzz finding (packetRecvServer): a ClientHello'/ServerHello' whose inner lengths overrun the message threw IndexOutOfBoundsException out of the core. */
    @Test fun truncatedHelloFailsInsteadOfThrowing() {
        // [type][u24 length 16][alpn list length 11][len 10 "hq-interop"][tp length 0x4848, beyond the body]
        val body = byteArrayOf(0, 11, 10) + "hq-interop".encodeToByteArray() + byteArrayOf(0x48, 0x48, 1)
        for ((role, type) in listOf(TlsRole.Server to 1, TlsRole.Client to 2)) {
            val session =
                NullCryptoProvider.newSession(
                    if (role ==
                        TlsRole.Server
                    ) {
                        server(listOf("hq-interop"))
                    } else {
                        client(listOf("hq-interop"))
                    },
                )
            try {
                session.setTransportParameters(ByteArray(0))
                if (role == TlsRole.Client) {
                    session.drive()
                    while (session.nextEvent() != null) { /* ClientHello' */ }
                }
                val hello = if (type == 1) body else body.copyOfRange(2, body.size) // ServerHello' has a single ALPN
                session.provide(EncryptionLevel.Initial, byteArrayOf(type.toByte(), 0, 0, hello.size.toByte()) + hello)
                assertIs<DriveResult.Failed>(session.drive())
            } finally {
                session.close()
            }
        }
        // an ALPN entry running past the list is malformed as well
        val s = NullCryptoProvider.newSession(server(listOf("hq-interop")))
        try {
            s.setTransportParameters(ByteArray(0))
            s.provide(EncryptionLevel.Initial, byteArrayOf(1, 0, 0, 3, 0, 1, 9))
            assertIs<DriveResult.Failed>(s.drive())
        } finally {
            s.close()
        }
    }
}
