// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.QuicConnection
import kotlinx.coroutines.CoroutineScope

/**
 * How the client engine's HTTP/3 connections follow the device's network (connection migration, RFC 9000 section 9;
 * docs/guide/ktor.md, "Connection migration"): set it with `engine { http3 { connectionMigration = ... } }`. Off (null) by
 * default, as in 0.2: a connection then stays on its first socket, which is bound to no network, so it lives on only if
 * the system routes that socket over the new network and the server follows the new address as a NAT rebinding; it
 * may also die at its idle timeout.
 *
 * The engine calls [start] for every pooled HTTP/3 connection once its handshake has completed (a 0-RTT connection is
 * handed to requests earlier, its migration waits), collects the migrator's [NetworkMigrator.events] into
 * [KuicksilverEventListener.connectionMigrated] (a [MigrationEvent.Failed] and a [MigrationEvent.SourceFailed] are also
 * logged, at `Info`; the transport's refusal of a server that does not allow migration at `Debug`), starts it unless
 * [start] already did, and closes it when the connection ends or the client is closed.
 * The QUIC rules hold whatever the hook does: the transport refuses a new path before the handshake is confirmed, towards a
 * server that sent `disable_active_migration` or uses zero-length connection IDs (a [MigrationEvent.Failed] then, no packet
 * leaves the new socket), validates every new path before the connection sends on it, and keeps the connection on its
 * path when validation fails. A migration neither marks an alternative broken nor clears marks: give
 * [Http3ClientConfig.networkId] the same source for that (on Android `networkId = { connectivity.activeNetwork?.toString() }`).
 *
 * The factories `Http3ConnectionMigration.followDefaultNetwork(connectivity)` (Android, `ConnectivityManager`) and
 * `Http3ConnectionMigration.followDefaultNetwork()` (iOS and macOS, `NWPathMonitor`) follow the system's default network.
 * Other platforms have no factory: build a [NetworkMigrator] over a source of your own, for example
 * `Http3ConnectionMigration { c, scope -> NetworkMigrator(c, myNetworks, { DatagramIo.open(myAddressOn(it)) }, scope) }`.
 *
 * Only HTTP/3 survives a network change: HTTP/1.1, HTTP/2 and WebSockets over HTTP/1.1 run over TCP, which cannot move,
 * and the dedicated connections of WebTransport sessions do not follow either.
 */
@ExperimentalKuicksilverApi
public fun interface Http3ConnectionMigration {
    /**
     * Sets up following networks for the new client [connection]: returns its [NetworkMigrator], whose jobs run in [scope]
     * (cancelled when the connection ends). Return it without starting it: the engine starts it once it listens to its
     * events, so none is missed (one already started is used as is). A hook that throws leaves the connection where it
     * is; the engine logs the failure at `Info`.
     */
    public fun start(
        connection: QuicConnection,
        scope: CoroutineScope,
    ): NetworkMigrator<*>

    /** Holds the platform factories (`followDefaultNetwork`). */
    public companion object
}
