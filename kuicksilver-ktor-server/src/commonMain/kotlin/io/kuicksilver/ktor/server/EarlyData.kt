// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.request.ApplicationRequest
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

internal val ReceivedEarlyKey: AttributeKey<Boolean> = AttributeKey("io.kuicksilver.ktor.server.ReceivedEarly")

/**
 * True when this HTTP/3 request arrived in 0-RTT and runs before the handshake completed (`quicEarlyData`, ADR-0015):
 * it may be a replay (RFC 8446 section 8). Only requests the `http3Settings.earlyData` policy declares replayable (GET,
 * HEAD and OPTIONS by default) get here early; the engine never adds `Early-Data: 1` itself (it is an origin, RFC 8470).
 */
@ExperimentalKuicksilverApi
public val ApplicationRequest.receivedEarly: Boolean get() = call.attributes.getOrNull(ReceivedEarlyKey) ?: false
