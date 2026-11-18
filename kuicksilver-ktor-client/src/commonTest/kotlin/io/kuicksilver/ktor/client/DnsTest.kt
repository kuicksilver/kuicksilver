// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/** The application resolver ([Dns]): its address type, and what the engine makes of its answers ([familyResolver]). */
class DnsTest {
    /**
     * [e] is [cause] or was caused by it: coroutines' stack-trace recovery (on the JVM with assertions on) rethrows a copy
     * of an exception that crossed a `Deferred`, with the original as its cause.
     */
    private fun assertCausedBy(
        cause: Throwable,
        e: Throwable,
    ) = assertTrue(generateSequence(e) { it.cause }.any { it === cause }, "$e is not caused by $cause")

    private fun ip(text: String) = IpAddress.parse(text)

    private fun tcp(text: String): TcpAddress = TcpAddress(ip(text).bytes, 0, ip(text).scopeId)

    @Test fun ipAddressParsesLiterals() {
        assertContentEquals(byteArrayOf(192.toByte(), 0, 2, 1), ip("192.0.2.1").bytes)
        assertFalse(ip("192.0.2.1").isIpv6)
        assertEquals("2001:db8::1", ip("[2001:db8::1]").toString())
        assertTrue(ip("2001:db8::1").isIpv6)
        assertEquals(3, ip("fe80::1%3").scopeId)
        assertEquals("fe80::1%3", ip("fe80::1%3").toString())
        assertEquals(ip("2001:db8::1"), IpAddress.of(ip("2001:0db8:0:0:0:0:0:1").bytes))
        // the bytes are a copy both ways
        val raw = byteArrayOf(10, 0, 0, 1)
        val a = IpAddress.of(raw)
        raw[0] = 11
        a.bytes[1] = 9
        assertEquals("10.0.0.1", a.toString())
    }

    @Test fun negative_ipAddressRefusesWhatIsNoLiteral() {
        for (bad in listOf(
            "example.com",
            "010.0.0.1",
            "1.2.3",
            "256.0.0.1",
            "0x7f.0.0.1",
            "fe80::1%eth0",
            "1::2::3",
            "",
            "[::1",
            "[1.2.3.4]",
        )) {
            assertFailsWith<IllegalArgumentException>(bad) { IpAddress.parse(bad) }
        }
        assertFailsWith<IllegalArgumentException> { IpAddress.of(ByteArray(5)) }
        assertFailsWith<IllegalArgumentException> { IpAddress.of(byteArrayOf(10, 0, 0, 1), scopeId = 1) }
    }

    /**
     * RFC 1122 section 3.2.1.3 ("this network" MUST NOT be sent except as a source address), RFC 4291 section 2.5.2 (the
     * unspecified address "must not be used as the destination address of IPv6 packets"), RFC 9293 section 3.9.1 (MUST-46:
     * a TCP OPEN for a broadcast or multicast remote address is an error): such answers are never a destination, also in
     * their IPv4-mapped form. Connecting to 0.0.0.0 reaches this host's own listeners on Linux and macOS.
     */
    @Test fun negative_unusableDestinationsAreDropped() {
        val answer =
            listOf(
                "0.0.0.0",
                "0.1.2.3",
                "::",
                "224.0.0.1",
                "239.255.255.250",
                "255.255.255.255",
                "ff02::1",
                "ff0e::1",
                "::ffff:0.0.0.0",
                "::ffff:224.0.0.1",
                "::ffff:255.255.255.255",
                "192.0.2.1",
            ).map(::ip)
        assertEquals(listOf(tcp("192.0.2.1")), usableAnswer(answer, ipv6 = null))
    }

    /** An IPv4-mapped answer is the IPv4 address (as the JDK's InetAddress makes it): it races and sorts as IPv4. */
    @Test fun ipv4MappedAnswersAreIpv4() {
        assertEquals(listOf(tcp("192.0.2.1")), usableAnswer(listOf(ip("::ffff:192.0.2.1")), ipv6 = false))
        assertEquals(emptyList(), usableAnswer(listOf(ip("::ffff:192.0.2.1")), ipv6 = true))
    }

    @Test fun duplicatesAreKeptOnceInTheResolversOrder() {
        val answer = listOf("192.0.2.2", "2001:db8::1", "192.0.2.1", "192.0.2.2", "::ffff:192.0.2.1", "2001:db8::1").map(::ip)
        assertEquals(listOf("192.0.2.2", "2001:db8::1", "192.0.2.1").map(::tcp), usableAnswer(answer, ipv6 = null))
    }

    /** A huge answer costs at most [MAX_DNS_ADDRESSES_PER_FAMILY] addresses of each family; the rest is not kept. */
    @Test fun negative_aHugeAnswerIsCappedPerFamily() {
        val many = List(100_000) { i -> IpAddress.of(byteArrayOf(10, (i shr 16).toByte(), (i shr 8).toByte(), i.toByte())) }
        val kept = usableAnswer(many + ip("2001:db8::1"), ipv6 = null)
        assertEquals(MAX_DNS_ADDRESSES_PER_FAMILY, kept.count { !it.isIpv6 })
        assertEquals(listOf(tcp("2001:db8::1")), kept.filter { it.isIpv6 })
        assertEquals(tcp("10.0.0.0"), kept.first())
    }

    /** A plain [Dns] answers both families in one call: the engine asks it once per name and splits the answer. */
    @Test fun aPlainDnsIsAskedOncePerNameForBothFamilies() =
        runBlocking {
            var asked = 0
            val resolve =
                Dns {
                    asked++
                    listOf(ip("192.0.2.1"), ip("2001:db8::1"))
                }.familyResolver()
            coroutineScope {
                val v6 = async(start = CoroutineStart.UNDISPATCHED) { resolve("h.test", true) }
                val v4 = async(start = CoroutineStart.UNDISPATCHED) { resolve("h.test", false) }
                assertEquals(listOf(tcp("2001:db8::1")), v6.await())
                assertEquals(listOf(tcp("192.0.2.1")), v4.await())
            }
            assertEquals(1, asked)
            resolve("other.test", true)
            assertEquals(2, asked)
        }

    /** A [FamilyDns] is asked for each family on its own (RFC 8305 section 3); an address of the other family is dropped. */
    @Test fun aFamilyDnsIsAskedPerFamily() =
        runBlocking {
            val asked = ArrayList<Pair<String, Boolean>>()
            val dns =
                object : FamilyDns {
                    override suspend fun lookup(
                        host: String,
                        ipv6: Boolean,
                    ): List<IpAddress> {
                        asked += host to ipv6
                        return listOf(ip("192.0.2.1"), ip("2001:db8::1"))
                    }
                }
            val resolve = dns.familyResolver()
            assertEquals(listOf(tcp("2001:db8::1")), resolve("h.test", true))
            assertEquals(listOf(tcp("192.0.2.1")), resolve("h.test", false))
            assertEquals(listOf("h.test" to true, "h.test" to false), asked)
            // its both-families lookup asks each family
            assertEquals(listOf(ip("2001:db8::1"), ip("192.0.2.1")), dns.lookup("x.test"))
        }

    /**
     * A host that has the shape of an IPv4 literal is never a host name (RFC 1123 section 2.1): one every platform reads
     * alike (`127.1`) is its address, one the platforms read differently (octal, hex) or that is no address fails, and the
     * resolver is asked for neither.
     */

    /**
     * A host that has the shape of an IPv4 literal is never a host name (RFC 1123 section 2.1): one every platform reads
     * alike (`127.1`) is its address, one the platforms read differently (octal, hex) or that is no address fails, and the
     * resolver is asked for neither; the engine decides this for every resolver ([RequestDns]). `0x` is one of them: glibc's
     * inet_aton reads it as 0.0.0.0, other parsers as a name (`AltSvcDestinationTest` refuses it alike).
     */
    @Test fun negative_aNumericHostIsNeverAskedFor() =
        runBlocking {
            val asked = ArrayList<String>()
            val dns =
                RequestDns(
                    Nat64.offForTest(),
                    { RequestDns.dualStackSortForTest() },
                    resolveFamily =
                        Dns { host ->
                            asked += host
                            listOf(ip("192.0.2.1"))
                        }.familyResolver(),
                )
            assertEquals(listOf("127.0.0.1:80"), dns.lookup("127.1", 80).map { it.toString() })
            assertEquals(listOf("127.0.0.1:80"), dns.lookup("2130706433", 80).map { it.toString() })
            for (bad in listOf("010.0.0.1", "0x7f.0.0.1", "256.1.1.1", "1.2.3.4.5", "0x")) {
                assertFailsWith<IOException>(bad) { dns.lookup(bad, 80) }
            }
            assertEquals(emptyList(), asked)
            assertEquals(listOf("192.0.2.1:80"), dns.lookup("x0", 80).map { it.toString() })
            assertEquals(listOf("x0"), asked)
        }

    @Test fun negative_aDnsFailureIsTheLookupsFailure() =
        runBlocking {
            val boom = IOException("boom")
            assertCausedBy(boom, assertFailsWith<IOException> { Dns { throw boom }.familyResolver()("h.test", true) })
            val odd = IllegalStateException("odd")
            assertCausedBy(odd, assertFailsWith<IOException> { Dns { throw odd }.familyResolver()("h.test", true) })
        }

    /**
     * A resolver whose own timeout throws a [CancellationException] (`withTimeout` inside it) while the caller is still
     * active has failed: the lookup fails with an [IOException], it does not pass for the caller's cancellation (which
     * would end the call as cancelled, or be swallowed by a race as a cancelled attempt).
     */
    @Test fun negative_aCancellationTheDnsThrowsOnItsOwnIsAFailure() =
        runBlocking {
            val own = CancellationException("the resolver's own timeout")
            assertCausedBy(own, assertFailsWith<IOException> { Dns { throw own }.familyResolver()("h.test", false) })
        }

    @Test fun aCancelledCallerCancelsTheLookup() =
        runBlocking {
            val entered = CompletableDeferred<Unit>()
            val cancelled = CompletableDeferred<Unit>()
            val resolve =
                Dns {
                    entered.complete(Unit)
                    try {
                        awaitCancellation()
                    } finally {
                        cancelled.complete(Unit)
                    }
                }.familyResolver()
            val call = async { resolve("h.test", true) }
            entered.await()
            call.cancel()
            cancelled.await()
            assertTrue(call.isCancelled)
        }

    @Test fun systemDnsAnswersLiteralsWithoutALookup() =
        runBlocking {
            assertEquals(listOf(ip("127.0.0.1")), Dns.System.lookup("127.0.0.1"))
            assertEquals(listOf(ip("::1")), Dns.System.lookup("[::1]"))
            assertEquals(emptyList(), (Dns.System as FamilyDns).lookup("127.0.0.1", ipv6 = true))
        }

    /**
     * [Dns.blocking] runs the lookup on a thread of its own dispatcher: a caller that stops waiting (its connect timeout)
     * is not held by a lookup that never returns, which goes on to its end on that thread.
     */
    @Test fun negative_aBlockingDnsThatNeverReturnsDoesNotHoldTheCaller() =
        runBlocking {
            val gate = CompletableDeferred<Unit>()
            val entered = CompletableDeferred<Unit>()
            val returned = CompletableDeferred<Unit>()
            val dns =
                Dns.blocking {
                    entered.complete(Unit)
                    runBlocking { gate.await() }
                    returned.complete(Unit)
                    listOf(ip("192.0.2.1"))
                }
            assertNull(withTimeoutOrNull(200.milliseconds) { dns.lookup("h.test") })
            entered.await()
            assertFalse(returned.isCompleted)
            gate.complete(Unit)
            returned.await()
        }

    /**
     * A caller that stops waiting for a blocking lookup takes it off the queue: a lookup still waiting for a thread of the
     * dispatcher never runs. Before, every such caller left a lookup behind that ran later for nobody, so a resolver that
     * hangs held the dispatcher's threads with lookups nobody waited for, request after request.
     */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun negative_aCallerThatStopsWaitingLeavesNoQueuedBlockingLookup() =
        runBlocking {
            val threads = 2
            val gate = CompletableDeferred<Unit>()
            val entered = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.UNLIMITED)
            val ran = kotlin.concurrent.atomics.AtomicInt(0)
            val dns =
                Dns.blocking(
                    kotlinx.coroutines.Dispatchers.Default
                        .limitedParallelism(threads),
                ) {
                    ran.addAndFetch(1)
                    entered.trySend(Unit)
                    runBlocking { gate.await() }
                    listOf(ip("192.0.2.1"))
                }
            coroutineScope {
                // the dispatcher's threads, all held by lookups whose callers wait
                val holders = List(threads) { async { dns.lookup("held.test") } }
                repeat(threads) { entered.receive() }
                // callers that give up while their lookups wait for a thread
                repeat(5) { assertNull(withTimeoutOrNull(50.milliseconds) { dns.lookup("queued.test") }) }
                gate.complete(Unit)
                holders.forEach { it.await() }
                // a lookup queued now runs after any that were left in the queue
                assertEquals(listOf(ip("192.0.2.1")), dns.lookup("after.test"))
            }
            assertEquals(threads + 1, ran.load(), "lookups whose callers had gone still ran")
        }

    @Test fun blockingDnsAnswers() =
        runBlocking {
            assertEquals(listOf(ip("192.0.2.1")), Dns.blocking { listOf(ip("192.0.2.1")) }.lookup("h.test"))
            val boom = IOException("boom")
            assertCausedBy(boom, assertFailsWith<IOException> { Dns.blocking { throw boom }.lookup("h.test") })
        }
}
