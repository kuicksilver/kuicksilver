// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:JvmName("AndroidNetworks")

package io.kuicksilver.quic

import android.net.ConnectivityManager
import android.net.Network
import android.os.ParcelFileDescriptor
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext

/**
 * Binds [local] on [network] (Android): every datagram of the socket leaves through that network whatever the default
 * network is (`Network.bindSocket`), so a connection can move to a network before the system switches to it. The
 * accelerated transport when [prefer] asks for it and the device has it, the portable one otherwise; throws the
 * `IOException` of `bindSocket` when the network is gone, the socket closed.
 */
@ExperimentalKuicksilverApi
public suspend fun DatagramIo.Companion.open(
    local: InetSocketAddress,
    network: Network,
    prefer: IoPreference = IoPreference.Accelerated,
): DatagramIo =
    withContext(Dispatchers.IO) {
        // the accelerated socket is bound already; its fd is borrowed through a dup that is closed again (the socket keeps the mark)
        val accelerated =
            if (prefer == IoPreference.Accelerated) {
                KslDatagramIo.open(local) { fd -> ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) } }
            } else {
                null
            }
        accelerated ?: NioDatagramIo.open(local) { channel -> network.bindSocket(channel.socket()) }
    }

/**
 * The device's default network (`ConnectivityManager.registerDefaultNetworkCallback`, API 24) as a [NetworkMigrator]
 * source: the current default first, then each new one, null while there is none. All collectors of one manager share a
 * single callback (Android allows about 100 per app, so one per connection would run out in a large pool); it is registered
 * with the first collector and unregistered when the last one stops. When registering throws (`TooManyRequestsException`),
 * every current collection ends with that exception and the next collection tries again; a [NetworkMigrator] reports it as
 * [MigrationEvent.SourceFailed]. Needs `ACCESS_NETWORK_STATE`, which the library manifest declares.
 */
@ExperimentalKuicksilverApi
public fun ConnectivityManager.defaultNetworks(): Flow<Network?> = sharedDefaultNetworks[this]

/** One default-network callback per manager. */
private val sharedDefaultNetworks = SharedPerKey<ConnectivityManager, Network?> { it.registerDefaultNetworks() }

private fun ConnectivityManager.registerDefaultNetworks(): Flow<Network?> =
    defaultNetworkUpdates { available, lost ->
        val callback =
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = available(network)

                override fun onLost(network: Network) = lost(network)
            }
        registerDefaultNetworkCallback(callback)
        return@defaultNetworkUpdates { unregisterNetworkCallback(callback) }
    }

/**
 * Keeps this client connection on the device's default network: a started [NetworkMigrator] over
 * [ConnectivityManager.defaultNetworks] that opens each new socket with [DatagramIo.Companion.open] bound to the new network
 * (at [local]: the wildcard address of the server's family by default, any port). The default network when this is called is
 * taken as the one the connection is on (an unbound socket follows the default network). Collect
 * [NetworkMigrator.events] right after this call to see every event; [NetworkMigrator.close] stops following.
 */
@ExperimentalKuicksilverApi
public fun QuicConnection.followDefaultNetwork(
    connectivity: ConnectivityManager,
    scope: CoroutineScope,
    local: InetSocketAddress? = null,
    prefer: IoPreference = IoPreference.Accelerated,
): NetworkMigrator<Network> {
    val bindTo = local ?: wildcardLocal()
    return NetworkMigrator(this, connectivity.defaultNetworks(), { n -> DatagramIo.open(bindTo, n, prefer) }, scope).also { it.start() }
}
