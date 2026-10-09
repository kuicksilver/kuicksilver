// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.tls.TlsRole

/** Stream identifier bits (RFC 9000 section 2.1): bit 0 = server-initiated, bit 1 = unidirectional. */
internal object StreamIds {
    fun isClientInitiated(id: Long): Boolean = id and 0x1L == 0L

    fun isBidi(id: Long): Boolean = id and 0x2L == 0L

    fun of(
        initiator: TlsRole,
        bidi: Boolean,
        index: Long,
    ): Long = (index shl 2) or (if (initiator == TlsRole.Server) 1L else 0L) or (if (bidi) 0L else 2L)

    fun index(id: Long): Long = id ushr 2

    fun isLocal(
        id: Long,
        role: TlsRole,
    ): Boolean = isClientInitiated(id) == (role == TlsRole.Client)
}
