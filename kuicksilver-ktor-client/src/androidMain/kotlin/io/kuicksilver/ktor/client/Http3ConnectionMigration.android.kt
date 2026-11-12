// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.net.ConnectivityManager
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.defaultNetworks
import io.kuicksilver.quic.open
import io.kuicksilver.quic.wildcardLocal
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow

/**
 * HTTP/3 connections follow the device's default network (Android): each connection gets a [NetworkMigrator] over
 * [ConnectivityManager.defaultNetworks] (one system callback per manager, shared by every connection) that opens the socket
 * for a new network bound to it (`Network.bindSocket`) and migrates there, as `QuicConnection.followDefaultNetwork` does.
 * Needs `ACCESS_NETWORK_STATE`, which the library manifest declares. The same source is the engine's network
 * ([Http3ConnectionMigration.networks]) unless `networkId` is set: a new default network resets the broken marks of `Alt-Svc`
 * alternatives and drops those without `persist=1`. The engine also takes the network's NAT64 prefix from [connectivity]
 * (`LinkProperties.getNat64Prefix`, API 30), for Happy Eyeballs on an IPv6-only network without 464XLAT.
 * Get the manager from the application's context
 * (`context.applicationContext.getSystemService(ConnectivityManager::class.java)`), not an Activity's, which the engine
 * would keep alive.
 */
@ExperimentalKuicksilverApi
public fun Http3ConnectionMigration.Companion.followDefaultNetwork(connectivity: ConnectivityManager): Http3ConnectionMigration {
    AndroidConnectivity.manager = connectivity // also where the network's NAT64 prefix comes from (platformNat64Prefixes)
    return object : Http3ConnectionMigration {
        override fun start(
            connection: QuicConnection,
            scope: CoroutineScope,
        ): NetworkMigrator<*> {
            @OptIn(InternalKuicksilverApi::class)
            val bindTo = connection.wildcardLocal()
            return NetworkMigrator(connection, connectivity.defaultNetworks(), { n -> DatagramIo.open(bindTo, n) }, scope)
        }

        override val networks: Flow<Any?> = connectivity.defaultNetworks()
    }
}
