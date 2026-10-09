// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

/** A decoding failure that closes the connection with [code] (RFC 9000 section 20.1); [frameType] names the frame being parsed. */
internal class QuicWireException(
    val code: Long,
    val frameType: Long,
    message: String,
) : Exception(message)
