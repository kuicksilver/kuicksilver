// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig

/**
 * The telemetry protocol, the real-time shape the library was designed for: a reliable control stream of text lines
 * (`HELLO <name>` → `WELCOME <name>`, `BYE` → `BYE`), sensor readings as DATAGRAM frames (`<key>=<value>`, only the
 * latest per key matters), and bulk media on unidirectional streams.
 */
object Protocol {
    /** The ALPN token both sides offer; QUIC requires one. */
    const val ALPN: String = "telemetry/1"
    /** The name the server certificate carries and the client checks. */
    const val SERVER_NAME: String = "telemetry.test"
    /** CONNECTION_CLOSE application code for a normal goodbye. */
    const val CLOSE_OK: Long = 0

    fun encodeReading(key: String, value: Double): ByteArray = "$key=$value".encodeToByteArray()

    /** null for anything that is not `<key>=<number>`: datagrams come from the network, never trust them. */
    fun decodeReading(bytes: ByteArray): Pair<String, Double>? {
        val text = bytes.decodeToString(); val eq = text.indexOf('=')
        if (eq <= 0) return null
        val value = text.substring(eq + 1).toDoubleOrNull() ?: return null
        return text.substring(0, eq) to value
    }
}

/** TLS for both sides, from PEM text as an application would load it from files. */
object TelemetryTls {
    fun client(): TlsConfig = tlsConfig(TlsRole.Client) {
        alpn = listOf(Protocol.ALPN)
        serverName = Protocol.SERVER_NAME
        trust = TrustConfig.AnchoredCa(Certificate.parsePem(SampleCerts.caPem))
    }

    fun server(): TlsConfig = tlsConfig(TlsRole.Server) {
        alpn = listOf(Protocol.ALPN)
        identity = TlsIdentity.fromPem(SampleCerts.serverChainPem, SampleCerts.serverKeyPem.toCharArray())
    }
}
