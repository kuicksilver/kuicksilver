// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The demo's Migration screen without its UI, on an emulator (release gate): 20 MiB from the demo server on the host
 * (10.0.2.2) over Kuicksilver HTTP/3 with `followDefaultNetwork` and over OkHttp at once; at 30 % of the HTTP/3 download
 * the default network is switched off (`svc wifi disable`, or `svc data disable` when mobile data is the default). The
 * HTTP/3 download completes on the other network after a `connectionMigrated(Migrated)`; the OkHttp one fails. Switched
 * on again at the end.
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
    private fun hasTransport(transport: Int): Boolean =
        connectivity.allNetworks.any { connectivity.getNetworkCapabilities(it)?.hasTransport(transport) == true }

    private fun bothNetworks(): Boolean =
        hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)

    /** Waits until Wi-Fi and mobile data are both up (a radio switched on by an earlier run may still be coming up). */
    private suspend fun awaitBothNetworks(): Boolean {
        val ready = CompletableDeferred<Unit>()
        val callback =
            object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(
                    network: Network,
                    caps: NetworkCapabilities,
                ) {
                    if (bothNetworks()) ready.complete(Unit)
                }

                override fun onAvailable(network: Network) {
                    if (bothNetworks()) ready.complete(Unit)
                }
            }
        connectivity.registerNetworkCallback(NetworkRequest.Builder().build(), callback)
        try {
            if (bothNetworks()) ready.complete(Unit) // the callback reports the networks already up, this covers a race
            return withTimeoutOrNull(60.seconds) { ready.await() } != null
        } finally {
            connectivity.unregisterNetworkCallback(callback)
        }
    }

    private fun defaultRadio(): String =
        if (connectivity.getNetworkCapabilities(connectivity.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
            "wifi"
        } else {
            "data"
        }

    @Test fun http3SurvivesTheSwitchAndTcpDoesNot() =
        runBlocking {
            val port = InstrumentationRegistry.getArguments().getString("demoServerPort")?.toIntOrNull()
            assumeTrue("start the demo server on the host and pass -Pandroid.testInstrumentationRunnerArguments.demoServerPort=8443", port != null)
            assertTrue(awaitBothNetworks(), "the test needs Wi-Fi and mobile data both on (the stock emulator has them)")
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
            // 20 MiB at 2 MiB/s: about 10 s, time enough to switch at 30 %
            val path = "/bytes/${20L shl 20}?rate=${2L shl 20}"
            var radio: String? = null
            try {
                withTimeout(120.seconds) {
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
                    radio = defaultRadio()
                    shell("svc $radio disable")
                    val h3Done = h3Result.await()
                    val tcpDone = tcpResult.await()
                    Log.i("kuicksilver-demo", "after svc $radio disable: HTTP/3 $h3Done, OkHttp $tcpDone")
                    assertIs<DownloadResult.Completed>(h3Done, "the HTTP/3 download goes on over the other network")
                    assertEquals(20L shl 20, h3Done.bytes)
                    assertTrue(h3Done.protocol.startsWith("HTTP/3"), h3Done.protocol)
                    assertTrue(migrated.tryReceive().isSuccess, "connectionMigrated(Migrated) was heard")
                    assertIs<DownloadResult.Failed>(tcpDone, "the TCP download breaks with its network")
                }
            } finally {
                radio?.let { shell("svc $it enable") }
                h3.close()
                tcp.close()
            }
        }
}
