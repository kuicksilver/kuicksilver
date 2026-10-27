// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.request.ApplicationRequest
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

internal val ReceivedEarlyKey: AttributeKey<Boolean> = AttributeKey("io.kuicksilver.ktor.server.ReceivedEarly")

/**
 * The request field a gateway sets on a request it forwarded before its client's handshake completed (RFC 8470 section
 * 5.1); any instance or value counts as "1".
 */
internal const val EARLY_DATA_FIELD: String = "Early-Data"

/**
 * True when this request may be a replay of early data (RFC 9846 section 8): an HTTP/3 request that arrived in 0-RTT and
 * runs before the handshake completed (`quicEarlyData`, ADR-0015), or a request over HTTP/1.1 or HTTP/3 that a gateway
 * marked with `Early-Data` because it received it in early data on a previous hop (RFC 8470 section 5.1). Only requests
 * the `http3Settings.earlyData` policy declares replayable (GET, HEAD and OPTIONS by default; over HTTP/1.1 these methods)
 * get here so marked: any other request with `Early-Data` is answered with `425 Too Early` without reaching the
 * application, since waiting for this hop's handshake cannot make it safe. The engine never adds `Early-Data` itself.
 */
@ExperimentalKuicksilverApi
public val ApplicationRequest.receivedEarly: Boolean get() = call.attributes.getOrNull(ReceivedEarlyKey) ?: false
