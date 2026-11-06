// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.readAvailable
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * `Http3ConnectionMigration.followDefaultNetwork(connectivity)` on an emulator, against a server on the host
 * (`AndroidMigrationPeerMain`) that the emulator reaches as 10.0.2.2 through its own Wi-Fi or mobile network: a download over
 * HTTP/3 while the default network is switched off (`svc wifi disable`, or `svc data disable` when the mobile network is
 * the default) and the other one takes over. Run it with `:kuicksilver-ktor-client:androidMigrationDeviceTest`, which starts
 * the server and passes its port as the instrumentation argument `kslMigrationPeerPort`; without it (a plain
 * `connectedAndroidDeviceTest`) the tests are skipped, because a server inside the device is reached over loopback whatever
 * network the client's socket is bound to, which would prove nothing about routing. With the port, a device without both
 * Wi-Fi and a mobile network fails rather than skips, so the gate cannot pass without the switch. Needs both (the
 * stock emulator). The network is switched on again at the end.
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

    /** The host server's port; skipped without one, failed when the device cannot switch between Wi-Fi and mobile data. */
    private suspend fun peerPort(): Int {
        val port = InstrumentationRegistry.getArguments().getString("kslMigrationPeerPort")?.toIntOrNull()
        assumeTrue("run :kuicksilver-ktor-client:androidMigrationDeviceTest (a server on the host, 10.0.2.2)", port != null)
        // a network switched on again by the previous test may still be coming up
        withTimeoutOrNull(60.seconds) {
            while (!hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || !hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) delay(200)
        }
        // asked for on purpose (the gate passes the port): a device that cannot switch networks fails instead of passing silently
        assertTrue(
            connectivity.activeNetwork != null && hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
            "androidMigrationDeviceTest needs a device with Wi-Fi and mobile data both on (the stock emulator has them); " +
                "found: default ${connectivity.activeNetwork}, Wi-Fi ${hasTransport(NetworkCapabilities.TRANSPORT_WIFI)}, " +
                "mobile ${hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)}",
        )
        return port!!
    }

    /** `svc wifi` when Wi-Fi is the default network, `svc data` otherwise: the radio that switching off moves the default. */
    private fun defaultRadio(): String =
        if (connectivity.getNetworkCapabilities(connectivity.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
            "wifi"
        } else {
            "data"
        }

    /** Reads the body; [atTwo] completes once 2 MiB arrived (the server waits there for `/resume`). */
    private suspend fun download(
        c: HttpClient,
        url: String,
        atTwo: CompletableDeferred<Unit>,
    ): Long =
        c.prepareGet(url).execute { r ->
            assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
            val ch = r.bodyAsChannel()
            val b = ByteArray(64 * 1024)
            var n = 0L
            while (true) {
                val k = ch.readAvailable(b, 0, b.size)
                if (k < 0) break
                n += k
                if (n >= MIB_2) atTwo.complete(Unit)
            }
            ch.closedCause?.let { throw it }
            n
        }

    private fun client(
        listener: KuicksilverEventListener,
        migrate: Boolean,
    ) = testClient(Http3DiscoveryMode.Preferred, engine = {
        trust = TrustConfig.ExpectedName("server.test", ClientFixtures.trust) // the test certificate, reached as 10.0.2.2
        quic = quicConfig { maxIdleTimeout = 10.seconds }
        eventListener = listener
        http3 {
            hardDelay = Duration.INFINITE // HTTP/1.1 only after HTTP/3 failed
            if (migrate) {
                // guide:ktor:android-migration
                connectionMigration = Http3ConnectionMigration.followDefaultNetwork(connectivity)
                networkId = { connectivity.activeNetwork?.toString() }
            }
        }
    })

    @Test fun followsDefaultNetworkOnEmulator() =
        runBlocking {
            KslLoader.ensureLoaded()
            val port = peerPort()
            val default = connectivity.activeNetwork
            val radio = defaultRadio()
            val migrated = Channel<MigrationEvent.Migrated<*>>(Channel.UNLIMITED)
            val listener =
                object : KuicksilverEventListener() {
                    override fun connectionMigrated(
                        origin: String,
                        event: MigrationEvent<*>,
                    ) {
                        Log.i("kuicksilver", "migration of $origin: $event")
                        if (event is MigrationEvent.Migrated) migrated.trySend(event)
                    }
                }
            try {
                client(listener, migrate = true).use { c ->
                    withTimeout(120.seconds) {
                        val atTwo = CompletableDeferred<Unit>()
                        val body = async { download(c, "https://10.0.2.2:$port/big", atTwo) }
                        atTwo.await()
                        shell("svc $radio disable")
                        val e = migrated.receive()
                        assertEquals(default, e.old)
                        assertNotEquals(default, e.new)
                        // the rest of the body, and a new request, cross the new network on the same connection
                        assertEquals("HTTP/3", c.get("https://10.0.2.2:$port/resume").bodyAsText())
                        assertEquals(MIB_8.toLong(), body.await())
                    }
                }
            } finally {
                shell("svc $radio enable")
            }
        }

    /**
     * Without `connectionMigration` (0.2's behaviour), on the same switch: logs what happens to the download, for the guide's
     * claim about connections that do not migrate, and checks that nothing migrates. The engine's endpoint socket is bound
     * to no network, so the system may route it over the new default network and the server follow that as a NAT
     * rebinding: on the API 32 emulator (2026-11-06) the download completed that way, which is why the guide says such a
     * connection "may" die rather than that it does.
     */
    @Test fun withoutMigrationOnEmulator() =
        runBlocking {
            KslLoader.ensureLoaded()
            val port = peerPort()
            val radio = defaultRadio()
            val migrations = Channel<MigrationEvent<*>>(Channel.UNLIMITED)
            val listener =
                object : KuicksilverEventListener() {
                    override fun connectionMigrated(
                        origin: String,
                        event: MigrationEvent<*>,
                    ) {
                        migrations.trySend(event)
                    }
                }
            try {
                client(listener, migrate = false).use { c ->
                    withTimeout(120.seconds) {
                        val atTwo = CompletableDeferred<Unit>()
                        val body = async { runCatching { download(c, "https://10.0.2.2:$port/big", atTwo) } }
                        atTwo.await()
                        shell("svc $radio disable")
                        val resumed = runCatching { c.get("https://10.0.2.2:$port/resume") }
                        val outcome = body.await()
                        Log.i("kuicksilver", "without migration: resume=${resumed.map { it.version }} body=$outcome")
                        assertEquals(true, migrations.tryReceive().isFailure, "nothing migrates without the option")
                    }
                }
            } finally {
                shell("svc $radio enable")
            }
        }

    private companion object {
        const val MIB_2 = 2 * 1024 * 1024
        const val MIB_8 = 8 * 1024 * 1024
    }
}
