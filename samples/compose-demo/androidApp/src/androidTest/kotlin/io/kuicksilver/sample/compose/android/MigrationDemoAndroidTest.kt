// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.sample.compose.AndroidDemoPlatform
import io.kuicksilver.sample.compose.DemoServer
import io.kuicksilver.sample.compose.DownloadResult
import io.kuicksilver.sample.compose.Lane
import io.kuicksilver.sample.compose.download
import io.kuicksilver.sample.compose.kuicksilverLane
import io.kuicksilver.sample.compose.okHttpClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The demo's Migration screen without its UI, on an emulator (release gate): 20 MiB from the demo server on the host
 * (10.0.2.2) over Kuicksilver HTTP/3 with `followDefaultNetwork` and over OkHttp at once; at 30 % of the HTTP/3 download
 * the default network is switched off (`svc wifi disable`, or `svc data disable` when mobile data is the default). The
 * HTTP/3 connection migrates away from it (`connectionMigrated(Migrated)`, heard while the download still runs) and the
 * download completes on the other network; the OkHttp one fails. Switched on again at the end.
 *
 * Both downloads must run over the network that is switched off, so the test starts them only once the default is settled:
 * the emulator's Wi-Fi often never validates, and mobile data switched on again by an earlier run becomes the default when it
 * validates (as in `ClientMigrationAndroidTest`, 2026-11-06). A default that moved after the downloads started would leave
 * OkHttp's socket on the network that stays and the migration done before the switch; the test fails to say so.
 *
 * The OkHttp expectation rests on an assumption about Android, not on anything this repository controls: when a network
 * goes away, the system tears down the TCP sockets that ran over it (netd destroys them, so a read fails at once), and a
 * TCP connection cannot move to another address. If a system kept such a socket alive and routed it over the new network,
 * the download would stall until OkHttp's read timeout (10 s) and fail then; the test waits for that within its bound. A
 * run where OkHttp completes would mean the assumption is wrong for that system, and the test fails to say so.
 *
 * Needs the demo server on the host (`./gradlew -p samples/compose-demo :server:run`) and its port as the instrumentation
 * argument `demoServerPort` (`-Pandroid.testInstrumentationRunnerArguments.demoServerPort=8443`); skipped without it, since a
 * server inside the device is reached over loopback whatever network is on. With it, a device without both Wi-Fi and
 * mobile data fails rather than skips. An emulator switches networks unlike a phone (both are NATs on the same host), so
 * this is necessary, not sufficient: the manual check on a device is in the sample's README.
 */
@RunWith(AndroidJUnit4::class)
class MigrationDemoAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private fun shell(command: String) {
        // read to the end: the command has run once its output is closed
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    }

    @Suppress("DEPRECATION") // ConnectivityManager.allNetworks: no replacement for listing every network
    private fun hasTransport(
        transport: Int,
        validated: Boolean = false,
    ): Boolean =
        connectivity.allNetworks.any {
            val caps = connectivity.getNetworkCapabilities(it)
            caps?.hasTransport(transport) == true && (!validated || caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
        }

    /**
     * Waits until Wi-Fi is up and mobile data validated (a radio switched on by an earlier run may still be coming up): the
     * system makes mobile data the default when it validates and Wi-Fi is not (the emulator's often is not), which would move
     * the default under downloads started before.
     */
    private suspend fun awaitBothNetworks(): Boolean =
        withTimeoutOrNull(60.seconds) {
            while (!hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                !hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR, validated = true)
            ) {
                delay(200)
            }
        } != null

    /** `svc wifi` when [default] is Wi-Fi, `svc data` otherwise: the radio that switching off takes [default] away. */
    private fun defaultRadio(default: Network?): String =
        if (connectivity.getNetworkCapabilities(default)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
            "wifi"
        } else {
            "data"
        }

    /** For the log: the network and its transports and validation, as the system reports them now. */
    private fun describe(n: Network?): String = "$n ${n?.let { connectivity.getNetworkCapabilities(it) }}"

    @Test fun http3SurvivesTheSwitchAndTcpDoesNot(): Unit = // JUnit 4 runs only void methods; the block ends in assertIs
        runBlocking {
            val port = InstrumentationRegistry.getArguments().getString("demoServerPort")?.toIntOrNull()
            assumeTrue("start the demo server on the host and pass -Pandroid.testInstrumentationRunnerArguments.demoServerPort=8443", port != null)
            assertTrue(
                awaitBothNetworks(),
                "the test needs Wi-Fi and mobile data both on, mobile data validated (the stock emulator has them): " +
                    "Wi-Fi ${hasTransport(NetworkCapabilities.TRANSPORT_WIFI)}, " +
                    "mobile ${hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)}",
            )
            val server = DemoServer("10.0.2.2", httpsPort = port!!)
            val migrated = Channel<MigrationEvent.Migrated<*>>(Channel.UNLIMITED)
            val listener =
                object : KuicksilverEventListener() {
                    override fun connectionMigrated(
                        origin: String,
                        event: MigrationEvent<*>,
                    ) {
                        Log.i("kuicksilver-demo", "connectionMigrated $origin: $event")
                        if (event is MigrationEvent.Migrated) migrated.trySend(event)
                    }
                }
            val h3 = kuicksilverLane(AndroidDemoPlatform(context), server, migrate = true, listener = listener)
            val tcp = Lane("OkHttp (TCP)", "", okHttpClient(), server.https(""), isKuicksilver = false)
            // 20 MiB at 1 MiB/s: about 20 s, so about 14 s after the switch at 30 % for the network to go away and the
            // connection to move (and for OkHttp's 10 s read timeout, should a system keep its socket)
            val path = "/bytes/${20L shl 20}?rate=${1L shl 20}"
            var radio: String? = null
            try {
                withTimeout(120.seconds) {
                    // the network both downloads open their connections on (OkHttp's socket stays there)
                    val start = connectivity.activeNetwork
                    Log.i("kuicksilver-demo", "downloads start on ${describe(start)}")
                    val atThirty = CompletableDeferred<Unit>()
                    val h3Result =
                        async {
                            download(h3.client, h3.baseUrl + path, resume = false, onProgress = { got, total ->
                                if (total != null && got * 10 >= total * 3) atThirty.complete(Unit)
                            })
                        }
                    val tcpResult = async { download(tcp.client, tcp.baseUrl + path, resume = false) }
                    // the switch must come while the download runs: one that ended before 30 % (a fast path) fails here
                    val reachedThirty =
                        select {
                            atThirty.onAwait { true }
                            h3Result.onAwait { false }
                        }
                    assertTrue(reachedThirty, "the HTTP/3 download ended before 30 %: ${h3Result.await()}")
                    // read when switching: switching off another network than the one the downloads run on proves nothing
                    val default = connectivity.activeNetwork
                    assertEquals(
                        start,
                        default,
                        "the default network moved during the download (now ${describe(default)}); the downloads are not on it",
                    )
                    // only the migration away from the network switched off counts
                    while (migrated.tryReceive().isSuccess) {
                        // drain
                    }
                    radio = defaultRadio(default)
                    shell("svc $radio disable")
                    Log.i("kuicksilver-demo", "svc $radio disable (default was ${describe(default)})")
                    // heard while the download runs: a download that ends first never needed to move
                    val moved =
                        select<MigrationEvent.Migrated<*>?> {
                            migrated.onReceive { it }
                            h3Result.onAwait { null }
                        }
                    Log.i("kuicksilver-demo", "after svc $radio disable: $moved, default now ${describe(connectivity.activeNetwork)}")
                    assertNotNull(
                        moved,
                        "connectionMigrated(Migrated) before the HTTP/3 download ended (${h3Result.await()}); " +
                            "default now ${describe(connectivity.activeNetwork)}",
                    )
                    assertEquals(default, moved.old, "the connection left the network switched off")
                    assertNotEquals(default, moved.new)
                    val h3Done = h3Result.await()
                    val tcpDone = tcpResult.await()
                    Log.i("kuicksilver-demo", "HTTP/3 $h3Done, OkHttp $tcpDone")
                    assertIs<DownloadResult.Completed>(h3Done, "the HTTP/3 download goes on over the other network")
                    assertEquals(20L shl 20, h3Done.bytes)
                    assertTrue(h3Done.protocol.startsWith("HTTP/3"), h3Done.protocol)
                    assertIs<DownloadResult.Failed>(tcpDone, "the TCP download breaks with its network")
                }
            } finally {
                radio?.let { shell("svc $it enable") }
                h3.close()
                tcp.close()
            }
        }
}
