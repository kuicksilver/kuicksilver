// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import io.ktor.client.HttpClient
import io.kuicksilver.ktor.client.Http3ConnectionMigration
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.flow.Flow

/** The name the demo certificate carries: every client checks the demo server against it, whatever address it dials. */
const val DEMO_SERVER_NAME: String = "kuicksilver.local"

/** Where the demo server runs (server/DemoServer.kt): HTTPS and HTTP/3 on [httpsPort], plain HTTP/1.1 on [httpPort]. */
data class DemoServer(
    val host: String,
    val httpsPort: Int = 8443,
    val httpPort: Int = 8080,
) {
    private val authorityHost: String get() = if (':' in host) "[$host]" else host

    fun https(path: String): String = "https://$authorityHost:$httpsPort$path"

    fun http(path: String): String = "http://$authorityHost:$httpPort$path"
}

/**
 * One engine in a comparison: [client] reaches the demo server at [baseUrl] (https, or http for CIO on iOS); [note] says
 * what makes it differ from a plain TCP client, shown under its column.
 */
class Lane(
    val name: String,
    val note: String,
    val client: HttpClient,
    val baseUrl: String,
    val isKuicksilver: Boolean,
) : AutoCloseable {
    override fun close() = client.close()
}

/** What differs between Android and iOS: the reference engines, the network source, and connection migration. */
interface DemoPlatform {
    /** "Android" or "iOS". */
    val name: String

    /** Where the demo server is by default: the host machine as an emulator or a simulator reaches it. */
    val defaultHost: String

    /** A sentence under the Migration screen about this platform's reference engines. */
    val referenceNote: String

    /** `Http3ConnectionMigration.followDefaultNetwork(...)` of this platform. */
    fun migration(): Http3ConnectionMigration

    /** The current network for `networkId` (a new network gives alternatives marked broken a fresh chance). */
    fun networkId(): String?

    /** The default network as the system reports it, for display: a name, or "no network". */
    fun networks(): Flow<String>

    /** The TCP reference engines, trusting the demo CA only and checking [DEMO_SERVER_NAME] as Kuicksilver does. */
    fun referenceLanes(server: DemoServer): List<Lane>
}

/** The demo CA as the only trust anchor, checked against [DEMO_SERVER_NAME] whatever host the URL names (an emulator's 10.0.2.2, a LAN address). */
fun demoTrust(): TrustConfig = TrustConfig.ExpectedName(DEMO_SERVER_NAME, TrustConfig.AnchoredCa(Certificate.parsePem(DemoCerts.caPem)))

/**
 * Kuicksilver's Ktor engine for the demo: [discovery] (H3Only for the comparisons, Auto for the Diagnostics screen),
 * the demo CA or the platform's trust store, connection migration when [migration] is set, and the kill switch
 * [http3Allowed]. [listener] hears the engine's events (connectionMigrated among them).
 */
fun kuicksilverClient(
    trust: TrustConfig,
    discovery: Http3DiscoveryMode,
    migration: Http3ConnectionMigration?,
    networkId: (() -> String?)?,
    http3Allowed: () -> Boolean = { true },
    listener: KuicksilverEventListener? = null,
): HttpClient =
    HttpClient(Kuicksilver) {
        engine {
            this.trust = trust
            eventListener = listener
            http3 {
                this.discovery = discovery
                this.http3Allowed = http3Allowed
                connectionMigration = migration
                if (networkId != null) this.networkId = networkId
            }
        }
    }

/**
 * The Kuicksilver lane of a comparison: HTTP/3 only to the demo server (`H3Only`: a call that cannot go over HTTP/3 fails
 * instead of falling back to HTTP/1.1, so a TCP result is never shown in the HTTP/3 column), following the default
 * network when [migrate].
 */
fun kuicksilverLane(
    platform: DemoPlatform,
    server: DemoServer,
    migrate: Boolean,
    listener: KuicksilverEventListener?,
): Lane =
    Lane(
        name = "Kuicksilver (HTTP/3)",
        note = if (migrate) "connectionMigration = followDefaultNetwork()" else "no connection migration",
        client =
            kuicksilverClient(
                trust = demoTrust(),
                discovery = Http3DiscoveryMode.H3Only,
                migration = if (migrate) platform.migration() else null,
                networkId = if (migrate) platform::networkId else null,
                listener = listener,
            ),
        baseUrl = server.https(""),
        isKuicksilver = true,
    )
