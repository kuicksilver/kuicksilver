// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpStatusCode
import io.kuicksilver.ktor.server.h3.authorityHost
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.HostName
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.matchesHost

/** 421 Misdirected Request (RFC 9110 section 15.5.20). */
internal const val MISDIRECTED_REQUEST = 421

/** [MISDIRECTED_REQUEST] for a Ktor call. */
internal val MisdirectedRequestStatus = HttpStatusCode(MISDIRECTED_REQUEST, "Misdirected Request")

/**
 * The RFC 9110 section 7.4 check of one connection: [local] is the chain it presented (empty for a plain connection: no
 * https request is valid over it), [trustedGateway] the connector's exemption.
 */
internal class AuthorityCheck(
    private val local: List<Certificate>,
    private val trustedGateway: Boolean,
    private val sni: SniChoice? = null,
) {
    /** [misdirected] for a request whose target URI has [scheme] and [authority]: why it gets 421, or null. */
    fun rejection(
        scheme: String?,
        authority: String?,
    ): String? = misdirected(local, scheme, authority, trustedGateway, sni)
}

/**
 * A connection whose identity and TLS settings (client certificates, their trust) a connector's `sniSelector` chose for the
 * ClientHello's server_name [serverName] (null: it carried none). The selector may give every name a policy of its own,
 * and which one another name would get is not known without asking it again, so a request on this connection must be for
 * the name the policy was chosen for: a DNS name equal to [serverName], or an IP literal when there was no SNI (a client
 * sends none for an address, RFC 6066 section 3). Otherwise a client could reach a name that requires a client
 * certificate over a connection that asked for none, or the other way round: the connection context does not match the
 * request (RFC 9110 sections 7.4 and 15.5.20). nginx (`ssl_verify_client`) and Caddy (`strict_sni_host`) reject such
 * requests with 421 when client authentication is configured.
 */
internal class SniChoice(
    val serverName: String?,
) {
    private val name: HostName? =
        serverName?.let {
            try {
                HostName.normalize(it)
            } catch (_: TlsException) {
                null
            }
        }
    private val valid = serverName == null || name != null

    /** Whether a request for [host] may use this connection. */
    fun allows(host: HostName): Boolean = valid && if (host.isIpLiteral) serverName == null else host == name
}

/**
 * Why a request must be rejected with 421 (the text the engine logs at debug level), or null when it is served (RFC 9110 section 7.4): "a request for an "https" resource
 * MUST be rejected unless it has been received over a connection that has been secured via a certificate valid for that
 * target URI's origin". [scheme] is the target URI's scheme, [authority] its authority (`:authority`, or `Host`); [local] is
 * the chain this connection presented, as the handshake chose it (SNI override or identity snapshot). On a TLS
 * connection every request with an authority is checked, whatever its scheme: the call reports the connection's scheme,
 * `https`, so an `http://` target (absolute form, or `:scheme http`) for another host would reach the application as an
 * https call for it.
 *
 * The host is matched against the leaf's subjectAltName as a client checks it (RFC 9110 section 4.3.4, RFC 9525:
 * [matchesHost]); the port plays no part, a certificate names none. Not rejected: on a plain connection a scheme other
 * than `https`, a request
 * without an authority (its target URI takes the server's own, RFC 9112 section 3.3), and a connection from a trusted
 * gateway ([KuicksilverTlsConnector.trustedGateway], the exception section 7.4 makes). An authority whose host is no valid
 * reference identifier (not ASCII, malformed) cannot be valid for the certificate and is rejected. On a connection an
 * `sniSelector` set up ([sni]), the host must also be the name it was set up for ([SniChoice]).
 */
internal fun misdirected(
    local: List<Certificate>,
    scheme: String?,
    authority: String?,
    trustedGateway: Boolean,
    sni: SniChoice? = null,
): String? {
    if (trustedGateway || authority.isNullOrEmpty()) return null
    val prefix = "421 Misdirected Request for $authority"
    // a plain connection: only an https target is misdirected (no certificate secures it); http targets are its own
    val leaf =
        local.firstOrNull()
            ?: return if (scheme.equals("https", ignoreCase = true)) "$prefix: an https request over a plain connection" else null
    val text = authorityHost(authority)
    val host =
        try {
            HostName.normalize(text)
        } catch (_: TlsException) {
            return "$prefix: not a valid host name or address"
        }
    return when {
        // `127.0.0.1.` is a reg-name (RFC 3986 section 3.2.2: an IPv4address has no trailing dot), not the address
        !leaf.matchesHost(
            host,
        ) || (host.isIpLiteral && text.endsWith('.')) -> "$prefix: the certificate of this connection does not name it"

        sni != null && !sni.allows(host) -> "$prefix: the sniSelector chose this connection's TLS settings for another name"

        else -> null
    }
}
