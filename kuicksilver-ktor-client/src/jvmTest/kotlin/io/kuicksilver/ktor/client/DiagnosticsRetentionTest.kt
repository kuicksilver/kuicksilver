// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import java.lang.ref.WeakReference
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * The diagnostics are plain data: a response's and a failed call's exception's diagnostics name the QUIC connection but
 * never hold it, so once the client is closed the connection (its runtime, its core, its endpoint loop) can be collected
 * while the application still holds them.
 */
class DiagnosticsRetentionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun diagnosticsKeepNoConnectionAlive() =
        h3Test {
            val reached = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(module = {
                    routing {
                        get("/") { call.respondText("ok") }
                        get("/hold") {
                            reached.complete(Unit)
                            CompletableDeferred<Unit>().await() // until the connection is killed
                        }
                    }
                })
            val opened = java.util.concurrent.CopyOnWriteArrayList<WeakReference<Any>>()
            val listener =
                object : ConnectionListener {
                    override fun onOpened(connection: ConnectionInfo) {
                        opened += WeakReference(connection.connection)
                    }
                }
            val held = ArrayList<Any>() // what the application keeps: a response's diagnostics, a failure
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = { http3 { connectionListener = listener } }).use { c ->
                    // the whole diagnostics of a response (a handle kept past the call's end would show) and its snapshot
                    val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    held += d
                    held += assertIs<QuicConnectionSnapshot>(d.connection)
                    coroutineScope {
                        val failing = async { runCatching { c.get("https://127.0.0.1:$port/hold") }.exceptionOrNull() }
                        withTimeout(10.seconds) { reached.await() }
                        (c.engine as KuicksilverEngine)
                            .h3
                            .connectionsForTest()
                            .single()
                            .quic
                            .close(0x101, "killed")
                        val e = assertNotNull(withTimeout(10.seconds) { failing.await() })
                        held += assertNotNull(e.kuicksilverDiagnostics, "$e")
                        held += e
                    }
                }
            } finally {
                server.stop(100, 500)
            }
            val refs = opened.toList()
            assertNotNull(refs.firstOrNull())
            var tries = 0
            while (refs.any { it.get() != null } && tries++ < 200) {
                System.gc()
                ByteArray(1 shl 20) // a little pressure
                kotlinx.coroutines.yield()
            }
            for (r in refs) assertNull(r.get(), "a connection is still reachable while the diagnostics are held")
            assertNotNull(held.size) // held to here
        }
}
