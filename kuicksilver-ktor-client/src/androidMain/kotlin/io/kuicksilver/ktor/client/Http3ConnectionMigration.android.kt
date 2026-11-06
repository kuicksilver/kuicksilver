// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.net.ConnectivityManager
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.defaultNetworks
import io.kuicksilver.quic.open
import io.kuicksilver.quic.wildcardLocal

/**
 * HTTP/3 connections follow the device's default network (Android): each connection gets a [NetworkMigrator] over
 * [ConnectivityManager.defaultNetworks] (one system callback per manager, shared by every connection) that opens the socket
 * for a new network bound to it (`Network.bindSocket`) and migrates there, as `QuicConnection.followDefaultNetwork` does.
 * Needs `ACCESS_NETWORK_STATE`, which the library manifest declares. For the broken marks of `Alt-Svc` alternatives to
 * reset on the same changes, set `networkId = { connectivity.activeNetwork?.toString() }` too.
 */
@ExperimentalKuicksilverApi
public fun Http3ConnectionMigration.Companion.followDefaultNetwork(connectivity: ConnectivityManager): Http3ConnectionMigration =
    Http3ConnectionMigration { connection, scope ->
        @OptIn(InternalKuicksilverApi::class)
        val bindTo = connection.wildcardLocal()
        NetworkMigrator(connection, connectivity.defaultNetworks(), { n -> DatagramIo.open(bindTo, n) }, scope)
    }
