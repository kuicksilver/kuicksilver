// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.ios

import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TofuStore
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** How the client decides whether to trust a server; the app's trust toggle. */
enum class TrustMode {
    /** The system trust store through SecTrust (public sites). */
    PLATFORM,

    /** Only the sample's private CA (`certs/gen.sh`): the in-app server and another phone running this app. */
    SAMPLE_CA,

    /** Trust on first use: the first key seen for a name is remembered for this app run (a LAN peer with any certificate). */
    TOFU,
}

/** ALPN of the raw QUIC echo protocol the in-app server speaks next to `h3`. */
const val ECHO_ALPN: String = "kuicksilver-echo"

/** The name the sample certificate carries; used as the server name when the client dials an IP literal. */
const val SAMPLE_SERVER_NAME: String = "kuicksilver.local"

/** The TOFU memory of one app run; an app that keeps it would persist it (Keychain), and then declare that in its own manifest. */
internal class MemoryTofuStore : TofuStore {
    private val lock = Mutex()
    private val keys = HashMap<String, SpkiSha256>()
    override suspend fun get(name: String): SpkiSha256? = lock.withLock { keys[name] }
    override suspend fun put(name: String, pin: SpkiSha256) { lock.withLock { keys[name] = pin } }
}

internal fun isIpLiteral(host: String): Boolean = host.contains(':') || host.all { it.isDigit() || it == '.' }

internal fun clientTls(host: String, alpn: String, mode: TrustMode, tofu: TofuStore): TlsConfig = tlsConfig(TlsRole.Client) {
    this.alpn = listOf(alpn)
    // the sample certificate names kuicksilver.local, localhost, 127.0.0.1 and ::1: a LAN IP verifies against the name
    serverName = if (mode != TrustMode.PLATFORM && isIpLiteral(host)) SAMPLE_SERVER_NAME else host
    trust = when (mode) {
        TrustMode.PLATFORM -> TrustConfig.Platform
        TrustMode.SAMPLE_CA -> TrustConfig.AnchoredCa(Certificate.parsePem(SampleCerts.caPem))
        TrustMode.TOFU -> TrustConfig.Tofu(tofu)
    }
}

internal fun serverTls(): TlsConfig = tlsConfig(TlsRole.Server) {
    alpn = listOf("h3", ECHO_ALPN)
    identity = TlsIdentity.fromPem(SampleCerts.serverChainPem, SampleCerts.serverKeyPem.toCharArray())
}
