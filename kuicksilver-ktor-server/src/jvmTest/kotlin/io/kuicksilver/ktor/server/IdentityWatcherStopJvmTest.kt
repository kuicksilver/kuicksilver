// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/** The PEM watcher must not hold up the stop: a read that never returns (a hung NFS mount, a FIFO at the path) cannot be cancelled. */
class IdentityWatcherStopJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun TlsIdentity.Reloadable.isClosed() = runCatching { reload(current) }.exceptionOrNull() is IllegalStateException

    @Test fun stopCompletesWhileAWatcherReadIsBlocked() =
        serverTest {
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val dir =
                java.nio.file.Files
                    .createTempDirectory("kuicksilver-watch-stop")
                    .toFile()
                    .also { it.deleteOnExit() }
            val chain = java.io.File(dir, "chain.pem").apply { writeText(TestCerts.toPem("CERTIFICATE", TestCerts.server)) }
            val key = java.io.File(dir, "key.pem").apply { writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)) }
            val server =
                kuicksilverServer(null, configure = {
                    tls {
                        pemFiles(chain.path, key.path) // the engine's own identity, closed at its stop
                        reloadInterval = 1.hours
                        readTextForTest = {
                            entered.countDown()
                            release.await() // a coroutine's cancellation does not interrupt a thread blocked here
                            ""
                        }
                    }
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }, module = {})
            try {
                server.startSuspend(false)
                val r = checkNotNull(server.engine.engineTls.reloadableIdentity)
                val reading = withContext(Dispatchers.IO) { entered.await(20, TimeUnit.SECONDS) }
                assertTrue(reading, "the watcher's first read did not start within 20 s")
                server.stopSuspend(100, 500)
                // the server job ends, and its last step closes the identity, while the read is still blocked
                val closed =
                    withTimeoutOrNull(10.seconds) {
                        while (!r.isClosed()) yield()
                        true
                    }
                assertTrue(closed == true, "the stop did not finish (identity still open) while the watcher's read was blocked")
            } finally {
                release.countDown()
            }
        }
}
