// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * `TrustConfig.Tofu` remembers a key only for a first contact whose handshake completed: the server proved it holds the key
 * (CertificateVerify) and the handshake (Finished). The store used to be written when the chain was verified, before either, so a
 * first contact that failed later (here: the server's Finished corrupted on the way) still pinned the presented key.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class TofuCommitTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class MapStore : TofuStore {
        val m = HashMap<String, SpkiSha256>()

        override suspend fun get(name: String) = m[name]

        override suspend fun put(
            name: String,
            pin: SpkiSha256,
        ) {
            m[name] = pin
        }
    }

    /** Whether [d] ends with a whole Finished message (type 20, a 32- or 48-byte verify_data). */
    private fun endsWithFinished(d: ByteArray): Boolean =
        listOf(32, 48).any { n ->
            d.size >= n + 4 && d[d.size - n - 4].toInt() == 20 && d[d.size - n - 3].toInt() == 0 && d[d.size - n - 2].toInt() == 0 &&
                d[d.size - n - 1].toInt() == n
        }

    @Test fun negative_quicFirstContactThatFailsAfterTheCertificatePinsNothing() {
        val store = MapStore()
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client(TrustConfig.Tofu(store))), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        // the server's Handshake-level flight ends with its Finished: its last byte is changed on the way
        p.onEvent = { fromClient, ev ->
            if (!fromClient && ev is TlsEvent.CryptoData && ev.level == EncryptionLevel.Handshake && endsWithFinished(ev.data)) {
                ev.data[ev.data.size - 1] = (ev.data[ev.data.size - 1].toInt() xor 0x01).toByte()
            }
        }
        var verified = false
        try {
            val (rc, _) =
                p.run { want ->
                    verified = true
                    runBlocking { p.c.verifyPeer(want.chain) }
                }
            assertTrue(verified, "the chain was verified before the Finished")
            assertTrue(rc is DriveResult.Failed && !p.cs.done, "the corrupted Finished fails the handshake: $rc")
            runBlocking { p.c.commitTrust() } // as the runtime would, wrongly; a failed handshake commits nothing anyway
            assertNull(store.m["server.test"], "a first contact that failed pinned its key")
        } finally {
            p.close()
        }
    }

    @Test fun quicFirstContactPinsOnceTheHandshakeCompleted() {
        val store = MapStore()
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client(TrustConfig.Tofu(store))), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        try {
            p.run { want ->
                val r = runBlocking { p.c.verifyPeer(want.chain) }
                assertNull(store.m["server.test"], "nothing is stored while the handshake runs")
                r
            }
            assertTrue(p.cs.done)
            runBlocking { p.c.commitTrust() }
            assertNotNull(store.m["server.test"], "the completed first contact is remembered")
        } finally {
            p.close()
        }
    }

    /** Server to client through a relay that changes the last byte of the server's 4th protected record (its Finished). */
    private class CorruptingPair : ChannelPair() {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        private val raw = ByteChannel(autoFlush = true)
        private val toClient = ByteChannel(autoFlush = true)
        override val clientIn: ByteReadChannel get() = toClient
        override val serverOut: ByteWriteChannel get() = raw

        init {
            scope.launch {
                var protected = 0
                val header = ByteArray(5)
                try {
                    while (true) {
                        if (!readFully(raw, header)) break
                        val len = ((header[3].toInt() and 0xff) shl 8) or (header[4].toInt() and 0xff)
                        val body = ByteArray(len)
                        if (!readFully(raw, body)) break
                        if (header[0].toInt() == 0x17 && ++protected == 4) body[len - 1] = (body[len - 1].toInt() xor 0x01).toByte()
                        toClient.writeFully(header)
                        toClient.writeFully(body)
                    }
                } finally {
                    toClient.flushAndClose()
                }
            }
        }

        private suspend fun readFully(
            from: ByteReadChannel,
            into: ByteArray,
        ): Boolean {
            var off = 0
            while (off < into.size) {
                val n = from.readAvailable(into, off, into.size - off)
                if (n < 0) return false
                off += n
            }
            return true
        }

        fun close() = scope.cancel()
    }

    @Test fun negative_tcpFirstContactThatFailsAfterTheCertificatePinsNothing() {
        val store = MapStore()
        var asked = false
        val counting =
            object : TofuStore {
                override suspend fun get(name: String): SpkiSha256? {
                    asked = true
                    return store.get(name)
                }

                override suspend fun put(
                    name: String,
                    pin: SpkiSha256,
                ) = store.put(name, pin)
            }
        val pair = CorruptingPair()
        try {
            val (cd, sd) = connect(TcpFixtures.client { trust = TrustConfig.Tofu(counting) }, TcpFixtures.server(), pair)
            runBlocking {
                assertFailsWith<TlsException> { withTimeout(10.seconds) { cd.await() } }
                runCatching { withTimeout(10.seconds) { sd.await() } }.getOrNull()?.close()
            }
            assertTrue(asked, "the chain reached the store before the Finished")
            assertNull(store.m["server.test"], "a first contact that failed pinned its key")
        } finally {
            pair.close()
        }
    }

    @Test fun tcpFirstContactPinsOnceTheHandshakeCompleted() {
        val store = MapStore()
        val (cd, sd) = connect(TcpFixtures.client { trust = TrustConfig.Tofu(store) }, TcpFixtures.server())
        runBlocking {
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            assertEquals(1, store.m.size, "the completed first contact is remembered")
            c.close()
            s.close()
        }
    }

    @Test fun negative_tcpStoreThatFailsFailsTheConnection() {
        val boom = IllegalStateException("store unavailable")
        val failing =
            object : TofuStore {
                override suspend fun get(name: String): SpkiSha256? = null

                override suspend fun put(
                    name: String,
                    pin: SpkiSha256,
                ): Unit = throw boom
            }
        val (cd, sd) = connect(TcpFixtures.client { trust = TrustConfig.Tofu(failing) }, TcpFixtures.server())
        runBlocking {
            val e = runCatching { withTimeout(10.seconds) { cd.await() } }.exceptionOrNull()
            assertTrue(e != null && generateSequence(e) { it.cause }.any { it === boom }, "failed with the store's error: $e")
            runCatching { withTimeout(10.seconds) { sd.await() } }.getOrNull()?.close()
        }
    }
}
