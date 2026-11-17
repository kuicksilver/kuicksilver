// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * One QUIC server handshake's answer from [TlsConfig.sniSelector], made by [QuicTlsSession.selectSni] off the connection loop
 * and handed back to [QuicTlsSession.resumeSni] on it. It holds the native configuration built for the chosen identity:
 * [close] releases it when the selection is never resumed (the connection ended meanwhile); [QuicTlsSession.resumeSni] takes
 * it over, and closes it on every path.
 *
 * @property serverName the ClientHello's server name the selection was made for (RFC 6066 section 3; unverified input), null
 *   when it carried none.
 */
public class SniSelection internal constructor(
    internal val session: Any,
    public val serverName: String?,
    lease: KslContext.Lease?,
    internal val override: ServerTlsOverride?,
    /** The TLS alert that ends the handshake instead (`unrecognized_name`, `missing_extension`, `internal_error`), 0 for none. */
    internal val alert: Int,
    /**
     * Why the handshake ends with `alert`: its message is generic (a QUIC transport sends it to the client as the
     * CONNECTION_CLOSE reason phrase), the selector's own exception or the override's [TlsException.Config] is its cause.
     */
    internal val failure: TlsException?,
) : AutoCloseable {
    private val held = AtomicReference(lease)

    /** True once the chosen identity's configuration was released by [close] or taken over by [QuicTlsSession.resumeSni]. */
    @InternalKuicksilverApi
    public val isConsumed: Boolean get() = held.load() == null

    /** The configuration of the chosen identity, taken once (null afterwards, and for no override). */
    internal fun take(): KslContext.Lease? = held.exchange(null)

    /** Releases the chosen identity's native configuration unless [QuicTlsSession.resumeSni] took it; idempotent. */
    override fun close() {
        held.exchange(null)?.close()
    }
}

/**
 * Server: the server_name of the ClientHello the configuration's `sniSelector` chose this session's identity and settings
 * for (RFC 6066 section 3; unverified input), null when it carried none, no selector ran, or the session is not the
 * OpenSSL-backed one. The server engine holds requests on the connection to that name (RFC 9110 section 7.4), as over TCP
 * (`TlsConnection.sniSelectedFor`).
 */
@InternalKuicksilverApi
public val QuicTlsSession.sniSelectedFor: String? get() = (this as? KslQuicTlsSession)?.sniSelectedName

/** What a server does once its `sniSelector` answered `override` for `hello` (TCP and QUIC alike). */
internal sealed interface SniVerdict {
    /** The handshake goes on under `override`. */
    class Override(
        val override: ServerTlsOverride,
    ) : SniVerdict

    /** The handshake goes on under the configuration's own identity. */
    object Default : SniVerdict

    /** The handshake ends with TLS alert `alert`. */
    class Refuse(
        val alert: Int,
        val reason: String,
    ) : SniVerdict
}

/**
 * The server's rule for the selector's answer. An override is used. No override with a server name: RFC 6066 section 3 lets a
 * server that "does not recognize the server name" either abort with a fatal `unrecognized_name(112)` or go on; `null` from
 * the selector is that refusal. No override and no server name: the configuration's own [TlsConfig.identity]; a
 * configuration without one cannot answer a ClientHello that names no server, and RFC 9846 section 9.2 says "Servers
 * requiring this extension SHOULD respond to a ClientHello lacking a "server_name" extension by terminating the connection
 * with a "missing_extension" alert" (109).
 */
internal fun TlsConfig.sniVerdict(
    hello: ClientHelloInfo,
    override: ServerTlsOverride?,
): SniVerdict =
    when {
        override != null -> SniVerdict.Override(override)
        hello.serverName != null -> SniVerdict.Refuse(ALERT_UNRECOGNIZED_NAME, "unrecognized_name")
        identity == null -> SniVerdict.Refuse(ALERT_MISSING_EXTENSION, "missing_extension: no server_name")
        else -> SniVerdict.Default
    }

/** TLS alerts of the SNI decision (RFC 9846 section 6). */
internal const val ALERT_UNRECOGNIZED_NAME = 112
internal const val ALERT_MISSING_EXTENSION = 109
internal const val ALERT_INTERNAL_ERROR = 80
