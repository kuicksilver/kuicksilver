// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.nwPathUpdates
import io.kuicksilver.quic.open
import io.kuicksilver.quic.wildcardLocal

/**
 * HTTP/3 connections follow the system's default network (iOS, macOS): each connection gets a [NetworkMigrator] over
 * [nwPathUpdates] (one `NWPathMonitor` shared by every connection) that opens the socket for a new path bound to its
 * interface (`IP_BOUND_IF`) and migrates there, as `QuicConnection.followDefaultNetwork` does; it also replaces a socket
 * iOS reclaimed while the app was suspended. For the broken marks of `Alt-Svc` alternatives to reset on the same changes,
 * give `networkId` the same source.
 */
@ExperimentalKuicksilverApi
public fun Http3ConnectionMigration.Companion.followDefaultNetwork(): Http3ConnectionMigration =
    Http3ConnectionMigration { connection, scope ->
        @OptIn(InternalKuicksilverApi::class)
        val bindTo = connection.wildcardLocal()
        NetworkMigrator(connection, nwPathUpdates(), { k -> DatagramIo.open(bindTo, k.interfaceIndex) }, scope)
    }
