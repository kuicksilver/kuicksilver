// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.nwPathUpdates
import io.kuicksilver.quic.open
import io.kuicksilver.quic.wildcardLocal
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow

/**
 * HTTP/3 connections follow the system's default network (iOS, macOS): each connection gets a [NetworkMigrator] over
 * [nwPathUpdates] (one `NWPathMonitor` shared by every connection) that opens the socket for a new path bound to its
 * interface (`IP_BOUND_IF`) and migrates there, as `QuicConnection.followDefaultNetwork` does; it also replaces a socket
 * iOS reclaimed while the app was suspended. The same source is the engine's network ([Http3ConnectionMigration.networks])
 * unless `networkId` is set: a new default path (another interface) resets the broken marks of `Alt-Svc` alternatives and
 * drops those without `persist=1`.
 */
@ExperimentalKuicksilverApi
public fun Http3ConnectionMigration.Companion.followDefaultNetwork(): Http3ConnectionMigration =
    object : Http3ConnectionMigration {
        override fun start(
            connection: QuicConnection,
            scope: CoroutineScope,
        ): NetworkMigrator<*> {
            @OptIn(InternalKuicksilverApi::class)
            val bindTo = connection.wildcardLocal()
            return NetworkMigrator(connection, nwPathUpdates(), { k -> DatagramIo.open(bindTo, k.interfaceIndex) }, scope)
        }

        override val networks: Flow<Any?> = nwPathUpdates()
    }
