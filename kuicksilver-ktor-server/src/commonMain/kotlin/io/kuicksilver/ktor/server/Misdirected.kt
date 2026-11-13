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
) {
    /** [misdirected] for a request whose target URI has [scheme] and [authority]. */
    fun misdirected(
        scheme: String?,
        authority: String?,
    ): Boolean = misdirected(local, scheme, authority, trustedGateway)
}

/**
 * Whether a request received over TLS must be rejected with 421 (RFC 9110 section 7.4): "a request for an "https" resource
 * MUST be rejected unless it has been received over a connection that has been secured via a certificate valid for that
 * target URI's origin". [scheme] is the target URI's scheme, [authority] its authority (`:authority`, or `Host`); [local] is
 * the chain this connection presented, as the handshake chose it (SNI override or identity snapshot).
 *
 * The host is matched against the leaf's subjectAltName as a client checks it (RFC 9110 section 4.3.4, RFC 9525:
 * [matchesHost]); the port plays no part, a certificate names none. Not rejected: a scheme other than `https`, a request
 * without an authority (its target URI takes the server's own, RFC 9112 section 3.3), and a connection from a trusted
 * gateway ([KuicksilverTlsConnector.trustedGateway], the exception section 7.4 makes). An authority whose host is no valid
 * reference identifier (not ASCII, malformed) cannot be valid for the certificate and is rejected.
 */
internal fun misdirected(
    local: List<Certificate>,
    scheme: String?,
    authority: String?,
    trustedGateway: Boolean,
): Boolean {
    if (trustedGateway || !scheme.equals("https", ignoreCase = true) || authority.isNullOrEmpty()) return false
    val leaf = local.firstOrNull() ?: return true // an https request on a connection secured by no certificate (plain)
    val host =
        try {
            HostName.normalize(authorityHost(authority))
        } catch (_: TlsException) {
            return true
        }
    return !leaf.matchesHost(host)
}
