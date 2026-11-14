// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.util.logging.KtorSimpleLogger
import io.ktor.util.logging.Logger
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.OcspStapling
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The OCSP response file of `kuicksilver.tls.ocspStapling` ([OcspFileWatcher]): whether the response is stapled is logged
 * at the first look and at each change, and the file is read again on the reload interval. The RFC 6960 check itself is
 * `OcspStapling.isUsableFor` (kuicksilver-tls's RevocationTest); here it is a switch the test turns.
 */
class OcspFileWatcherTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val r1 = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
    private val r2 = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x02)

    private class Lines : Logger by KtorSimpleLogger("io.kuicksilver.test") {
        val lines = ArrayList<Pair<String, String>>()

        override fun warn(message: String) {
            lines += "WARN" to message
        }

        override fun info(message: String) {
            lines += "INFO" to message
        }

        override fun debug(message: String) {
            lines += "DEBUG" to message
        }

        fun count(level: String) = lines.count { it.first == level }
    }

    private var file: ByteArray? = r1
    private var usable = true
    private val log = Lines()
    private val stapling = OcspStapling(r1)

    private fun watcher(reread: Boolean = true) =
        OcspFileWatcher(
            "ocsp.der",
            stapling,
            { listOf(Certificate(TestCerts.server)) },
            log,
            reread,
            read = { file ?: throw IOException("ocsp.der: no such file") },
            usable = { s, _ -> usable && s.current != null },
        )

    @Test fun usableResponseIsQuietAtStartup() {
        watcher().checkUsable()
        assertEquals(0, log.count("WARN"), "${log.lines}")
    }

    /** A response that would not be stapled is a warning at startup, not a failure: handshakes go on without one. */
    @Test fun negative_unusableResponseWarnsAtStartup() {
        usable = false
        watcher().checkUsable()
        assertEquals(1, log.count("WARN"), "${log.lines}")
        assertTrue("is not stapled" in log.lines.single().second, "${log.lines}")
    }

    /** The file is read again on the interval: a new response replaces the stapled one, an unchanged one is left alone. */
    @Test fun changedFileIsStapledAfterTheReload() {
        val w = watcher()
        w.checkUsable()
        assertEquals(IdentityFileWatcher.Outcome.Unchanged, w.checkOnce())
        file = r2
        assertEquals(IdentityFileWatcher.Outcome.Reloaded, w.checkOnce())
        assertContentEquals(r2, stapling.current)
        assertTrue(log.lines.any { it.first == "INFO" && "reloaded from ocsp.der" in it.second }, "${log.lines}")
        assertEquals(IdentityFileWatcher.Outcome.Unchanged, w.checkOnce())
    }

    /** Without a reload interval the file is not read again, only whether the response is still stapled is watched. */
    @Test fun withoutRereadTheFileIsNotRead() {
        val w = watcher(reread = false)
        file = r2
        w.checkOnce()
        assertContentEquals(r1, stapling.current)
    }

    /**
     * A response that stops being stapled (it expired, or the certificate was reloaded and it is for the old one) is logged
     * once, not at every check, and its return once at info.
     */
    @Test fun negative_responseThatStopsBeingStapledIsLoggedOnce() {
        val w = watcher(reread = false)
        w.checkUsable()
        usable = false
        repeat(3) { w.checkOnce() }
        assertEquals(1, log.count("WARN"), "${log.lines}")
        assertTrue("no longer stapled" in log.lines.single { it.first == "WARN" }.second, "${log.lines}")
        usable = true
        repeat(2) { w.checkOnce() }
        assertEquals(1, log.lines.count { it.first == "INFO" && "stapled again" in it.second }, "${log.lines}")
    }

    /** A file that disappears or holds no DER SEQUENCE leaves the current response, warned once, then at debug level. */
    @Test fun negative_unreadableOrDamagedFileKeepsTheCurrentResponse() {
        val w = watcher()
        w.checkUsable()
        file = null
        repeat(2) { assertEquals(IdentityFileWatcher.Outcome.Failed, w.checkOnce()) }
        file = "not der".encodeToByteArray()
        assertEquals(IdentityFileWatcher.Outcome.Failed, w.checkOnce())
        assertContentEquals(r1, stapling.current)
        assertEquals(2, log.count("WARN"), "${log.lines}")
        assertEquals(1, log.count("DEBUG"), "${log.lines}")
    }

    /** The engine runs the startup check: a deployment port whose response is not for its certificate logs the warning. */
    @Test fun negative_engineWarnsAtStartupAboutAResponseItCannotStaple() =
        serverTest {
            val captured = CapturedLog()
            val server =
                kuicksilverServer(captured, configure = {
                    identity = ServerFixtures.identity()
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    http3 = false
                    tlsOcspStapling = OcspStapling(r1) // a DER SEQUENCE, but no OCSP response for TestCerts.server
                    tlsOcspFile = "ocsp.der"
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(false)
            try {
                captured.assertLogged("WARN", "ocsp.der", "is not stapled")
            } finally {
                server.stop(0, 500)
            }
        }
}
