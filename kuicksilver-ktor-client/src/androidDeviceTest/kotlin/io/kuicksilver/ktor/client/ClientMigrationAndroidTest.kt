// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.MigrationEvent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * `Http3ConnectionMigration.followDefaultNetwork(connectivity)` on an emulator: a download over HTTP/3 from a server in the
 * same process (loopback) while the default network is switched off (`svc wifi disable`, or `svc data disable` when the
 * mobile network is the default) and the other one takes over. The connection moves to a socket bound to the new default
 * network and the download completes. Needs a device with Wi-Fi and a mobile network (the stock emulator); skipped
 * elsewhere. The network is switched on again at the end.
 */
@RunWith(AndroidJUnit4::class)
class ClientMigrationAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val connectivity = instrumentation.targetContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private fun shell(command: String) {
        // read to the end: the command has run once its output is closed
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    }

    private fun hasTransport(transport: Int): Boolean =
        connectivity.allNetworks.any { connectivity.getNetworkCapabilities(it)?.hasTransport(transport) == true }

    @Test fun followsDefaultNetworkOnEmulator() =
        runBlocking {
            KslLoader.ensureLoaded()
            val default = connectivity.activeNetwork
            assumeTrue(
                "the device has Wi-Fi and a mobile network",
                default != null && hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
            )
            // the default network goes away: Wi-Fi off when it is the default, mobile data off otherwise
            val onWifi = connectivity.getNetworkCapabilities(default)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val radio = if (onWifi) "wifi" else "data"
            val atTwo = CompletableDeferred<Unit>()
            val resume = CompletableDeferred<Unit>()
            val (server, port) =
                testServer {
                    routing {
                        get("/big") {
                            call.respondBytesWriter {
                                val chunk = ByteArray(64 * 1024) { 7 }
                                var sent = 0
                                while (sent < MIB_8) {
                                    if (sent == MIB_2 && call.request.httpVersion == "HTTP/3") {
                                        atTwo.complete(Unit)
                                        resume.await()
                                    }
                                    writeFully(chunk)
                                    sent += chunk.size
                                }
                            }
                        }
                    }
                }
            val migrated = Channel<MigrationEvent.Migrated<*>>(Channel.UNLIMITED)
            val listener =
                object : KuicksilverEventListener() {
                    override fun connectionMigrated(
                        origin: String,
                        event: MigrationEvent<*>,
                    ) {
                        if (event is MigrationEvent.Migrated) migrated.trySend(event)
                    }
                }
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    eventListener = listener
                    http3 {
                        hardDelay = Duration.INFINITE // HTTP/1.1 only after HTTP/3 failed
                        // guide:ktor:android-migration
                        connectionMigration = Http3ConnectionMigration.followDefaultNetwork(connectivity)
                        networkId = { connectivity.activeNetwork?.toString() }
                    }
                }).use { c ->
                    withTimeout(120.seconds) {
                        val download =
                            async {
                                c.prepareGet("https://127.0.0.1:$port/big").execute { r ->
                                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                                    val ch = r.bodyAsChannel()
                                    val b = ByteArray(64 * 1024)
                                    var n = 0L
                                    while (true) {
                                        val k = ch.readAvailable(b, 0, b.size)
                                        if (k < 0) break
                                        n += k
                                    }
                                    ch.closedCause?.let { throw it }
                                    n
                                }
                            }
                        atTwo.await()
                        shell("svc $radio disable")
                        val e = migrated.receive()
                        assertEquals(default, e.old)
                        assertNotEquals(default, e.new)
                        resume.complete(Unit)
                        assertEquals(MIB_8.toLong(), download.await())
                    }
                }
            } finally {
                resume.complete(Unit)
                shell("svc $radio enable")
                server.stop(100, 500)
            }
        }

    private companion object {
        const val MIB_2 = 2 * 1024 * 1024
        const val MIB_8 = 8 * 1024 * 1024
    }
}
