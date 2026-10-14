// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Session ticket keys live in `ksl` only (threat model 1, 3.7; security review 2026-10-14, finding 1): explicit keys are copied
 * there when the [SessionTicketConfig] is built and the caller's arrays are zeroed; generated keys never reach Kotlin.
 */
class TicketKeysTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private fun key(seed: Int): ByteArray = ByteArray(80) { (it * 31 + seed).toByte() }

    @Test fun explicitKeysAreZeroedOnConstruction() {
        val a = key(1)
        val b = key(2)
        SessionTicketConfig(keys = listOf(a, b))
        assertTrue(a.all { it == 0.toByte() } && b.all { it == 0.toByte() }, "the caller's key arrays are zeroed")
    }

    @Test fun negative_malformedKeysAreZeroedToo() {
        val good = key(3)
        val short = ByteArray(79) { 1 }
        assertFailsWith<TlsException.Config> { SessionTicketConfig(keys = listOf(good, short)) }
        assertTrue(good.all { it == 0.toByte() } && short.all { it == 0.toByte() }, "refused keys are zeroed as well")
        val bad = key(4)
        assertFailsWith<TlsException.Config> { SessionTicketConfig(keys = listOf(bad), rotateEvery = 8.seconds * 86400) }
        assertTrue(bad.all { it == 0.toByte() }, "keys of an otherwise invalid configuration are zeroed")
        assertFailsWith<TlsException.Config> { SessionTicketConfig(keys = emptyList()) }
    }

    /** Two processes (here: two configurations) with the same explicit keys resume each other's tickets. */
    @Test fun explicitKeysResumeAcrossConfigurations() {
        val client = TcpFixtures.client()
        val first = TcpFixtures.server { sessionTickets = SessionTicketConfig(keys = listOf(key(5), key(6))) }
        val second = TcpFixtures.server { sessionTickets = SessionTicketConfig(keys = listOf(key(5))) }
        assertFalse(once(client, first), "first connection is a full handshake")
        assertTrue(once(client, second), "a ticket under the same current key resumes on the other configuration")
    }

    @Test fun negative_otherExplicitKeysDoNotResume() {
        val client = TcpFixtures.client()
        assertFalse(once(client, TcpFixtures.server { sessionTickets = SessionTicketConfig(keys = listOf(key(7))) }))
        assertFalse(
            once(client, TcpFixtures.server { sessionTickets = SessionTicketConfig(keys = listOf(key(8))) }),
            "a ticket under other keys is not resumed",
        )
    }

    @Test fun generatedKeysResumeAcrossConnections() {
        val client = TcpFixtures.client()
        assertFalse(once(client, TcpFixtures.server()))
        assertTrue(once(client, TcpFixtures.server()), "each connection has its own context; the process keys are shared")
    }

    /** One connection; true when it resumed. Waits for the fresh ticket so the next call can resume. */
    private fun once(
        client: TlsConfig,
        server: TlsConfig,
    ): Boolean =
        runBlocking {
            val (cd, sd) = connect(client, server)
            val c = withTimeout(20.seconds) { cd.await() }
            val s = withTimeout(20.seconds) { sd.await() }
            c.output.writeFully(byteArrayOf(1), 0, 1)
            c.output.flush()
            s.input.readExactly(1)
            s.output.writeFully(byteArrayOf(2), 0, 1)
            s.output.flush()
            c.input.readExactly(1)
            val reused = c.sessionReused && s.sessionReused
            val key = SessionCache.key(client.serverName, "server.test", client.trust, client.identity)
            withTimeoutOrNull(5.seconds) { while (!SessionCache.Default.peek(key)) delay(10) }
            c.close()
            s.close()
            reused
        }
}
