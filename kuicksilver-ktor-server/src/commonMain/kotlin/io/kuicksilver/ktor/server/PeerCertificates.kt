// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.request.ApplicationRequest
import io.ktor.util.AttributeKey
import io.kuicksilver.tls.Certificate

internal val PeerCertificatesKey: AttributeKey<List<Certificate>> = AttributeKey("io.kuicksilver.ktor.server.PeerCertificates")

/**
 * The client certificate chain (leaf first) as the TLS layer validated it for this request's connection, over TCP or
 * QUIC; empty without client authentication. Ktor has no equivalent API.
 */
public val ApplicationRequest.peerCertificates: List<Certificate> get() = call.attributes.getOrNull(PeerCertificatesKey).orEmpty()
