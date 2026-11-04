// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.frame

import io.kuicksilver.http2.Http2ErrorCode

/** A connection error (RFC 9113 section 5.4.1): the connection ends with a GOAWAY carrying [code]. */
internal class H2ConnectionError(
    val code: Http2ErrorCode,
    message: String,
) : Exception(message)

/** A stream error (RFC 9113 section 5.4.2): stream [streamId] ends with a RST_STREAM carrying [code]. */
internal class H2StreamError(
    val streamId: Int,
    val code: Http2ErrorCode,
    message: String,
) : Exception(message)
