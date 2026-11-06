// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** `ksl_dns_query` through [KslDns]: the bound on lookups at once, the answer forms, and real lookups where they can run. */
class KslDnsTest {
    @AfterTest fun reset() {
        KslDns.queryForTest = null
    }

    @Test fun negative_concurrencyCapped() =
        runBlocking {
            val release = CountDownLatch(1)
            val entered = AtomicInteger()
            val fourIn = CompletableDeferred<Unit>()
            KslDns.queryForTest = { _, _, _, _ ->
                if (entered.incrementAndGet() == KslDns.MAX_CONCURRENT) fourIn.complete(Unit)
                release.await() // a resolver that hangs, blocking its thread
                byteArrayOf()
            }
            // undispatched: each caller takes its permit (or waits for one) before the next starts
            val calls =
                List(KslDns.MAX_CONCURRENT + 1) {
                    async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) { KslDns.query("a.example", 65, 30.seconds) }
                }
            withTimeout(10.seconds) { fourIn.await() }
            // the fifth waits for a permit: it cannot have entered while the four hold theirs
            assertEquals(KslDns.MAX_CONCURRENT, entered.get())
            assertEquals(KslDns.MAX_CONCURRENT, KslDns.inFlightForTest)
            release.countDown()
            withTimeout(10.seconds) { calls.awaitAll() }
            assertEquals(KslDns.MAX_CONCURRENT + 1, entered.get())
        }

    @Test fun negative_hangingLookupIsLeftBehindAtTheTimeout() =
        runBlocking {
            val release = CountDownLatch(1)
            KslDns.queryForTest = { _, _, _, _ ->
                release.await()
                byteArrayOf()
            }
            try {
                // the caller stops waiting (Windows' DnsQuery_W takes no timeout); the lookup ends on its own later
                assertNull(withTimeout(10.seconds) { KslDns.query("a.example", 65, 1.seconds) })
            } finally {
                release.countDown()
            }
        }

    @Test fun answerForms() {
        assertEquals(emptyList(), assertIs<KslDnsAnswer.Records>(KslDns.decode(byteArrayOf())).records)
        assertContentEquals(
            byteArrayOf(9, 8),
            assertIs<KslDnsAnswer.Message>(KslDns.decode(byteArrayOf(KslConst.DNS_MESSAGE.toByte(), 9, 8))).bytes,
        )
        val list =
            byteArrayOf(KslConst.DNS_RECORDS.toByte(), 0, 0, 1, 44, 3, 'a'.code.toByte(), '.'.code.toByte(), 'b'.code.toByte(), 0, 2, 7, 7)
        val r = assertIs<KslDnsAnswer.Records>(KslDns.decode(list)).records.single()
        assertEquals("a.b", r.owner)
        assertEquals(300, r.ttlSeconds)
        assertContentEquals(byteArrayOf(7, 7), r.rdata)
        for (n in 2 until list.size) assertNull(KslDns.decode(list.copyOf(n)), "cut at $n")
        assertNull(KslDns.decode(byteArrayOf(9)))
    }

    @Test fun fakeServerAnswerParses() {
        assumeTrue(System.getProperty("os.name").lowercase().startsWith("linux"), "a resolver address with a port: Linux only")
        KslLoader.ensureLoaded()
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { sock ->
            var queryId = -1
            val server =
                thread {
                    val q = DatagramPacket(ByteArray(512), 512)
                    sock.soTimeout = 5000
                    sock.receive(q)
                    queryId = (q.data[0].toInt() and 0xff) shl 8 or (q.data[1].toInt() and 0xff)
                    val r =
                        CANNED.copyOf().also {
                            it[0] = q.data[0]
                            it[1] = q.data[1]
                        }
                    sock.send(DatagramPacket(r, r.size, q.socketAddress))
                }
            val port = sock.localPort
            val addr =
                ByteArray(KslConst.UDP_ADDR_LEN).also {
                    it[0] = 4
                    it[2] = (port shr 8).toByte()
                    it[3] = port.toByte()
                    it[4] = 127
                    it[7] = 1
                }
            val answer = runBlocking { KslDns.query("a.example", 65, 2.seconds, addr) }
            server.join()
            val m = assertIs<KslDnsAnswer.Message>(answer).bytes
            assertEquals(queryId, (m[0].toInt() and 0xff) shl 8 or (m[1].toInt() and 0xff))
            assertContentEquals(CANNED.copyOfRange(2, CANNED.size), m.copyOfRange(2, m.size))
        }
    }

    @Test fun liveCloudflareHasH3() {
        assumeTrue(System.getenv("KSL_LIVE_DNS") == "1", "KSL_LIVE_DNS=1 asks the system resolver for cloudflare.com")
        KslLoader.ensureLoaded()
        val answer = runBlocking { KslDns.query("cloudflare.com", 65, 5.seconds) }
        val bytes =
            when (answer) {
                is KslDnsAnswer.Message -> answer.bytes
                is KslDnsAnswer.Records -> answer.records.fold(ByteArray(0)) { a, r -> a + r.rdata }
                null -> ByteArray(0)
            }
        assertTrue(
            (0 until bytes.size - 2).any {
                bytes[it].toInt() == 2 && bytes[it + 1] == 'h'.code.toByte() &&
                    bytes[it + 2] == '3'.code.toByte()
            },
            "no h3 in $answer",
        )
    }

    private companion object {
        /** A response to `a.example HTTPS IN` with one record `1 . alpn=h3` (the ID is the query's). */
        val CANNED =
            byteArrayOf(
                0,
                0,
                0x81.toByte(),
                0x80.toByte(),
                0,
                1,
                0,
                1,
                0,
                0,
                0,
                0,
                1,
                'a'.code.toByte(),
                7,
                'e'.code.toByte(),
                'x'.code.toByte(),
                'a'.code.toByte(),
                'm'.code.toByte(),
                'p'.code.toByte(),
                'l'.code.toByte(),
                'e'.code.toByte(),
                0,
                0,
                0x41,
                0,
                1,
                0xc0.toByte(),
                0x0c,
                0,
                0x41,
                0,
                1,
                0,
                0,
                1,
                0x2c,
                0,
                0x0a,
                0,
                1,
                0,
                0,
                1,
                0,
                3,
                2,
                'h'.code.toByte(),
                '3'.code.toByte(),
            )
    }
}
