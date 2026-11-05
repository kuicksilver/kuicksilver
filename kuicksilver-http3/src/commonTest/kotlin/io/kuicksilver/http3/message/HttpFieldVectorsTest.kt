// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import kotlin.test.Test
import kotlin.test.fail

/**
 * The shared field and message cases (tools/vectors/http-fields.json) against this module's validator: the HTTP/2 copy
 * (`io.kuicksilver.http2.message.H2Fields`, ADR-0017) runs the same cases, so the two cannot drift apart.
 */
class HttpFieldVectorsTest {
    private fun valid(block: () -> Unit): Boolean =
        try {
            block()
            true
        } catch (_: MalformedMessage) {
            false
        }

    private fun expect(
        what: String,
        input: Any,
        want: Boolean,
        got: Boolean,
    ) {
        if (want != got) fail("$what $input: expected ${if (want) "valid" else "malformed"}")
    }

    @Test fun names() = HttpFieldVectors.NAMES.forEach { expect("name", it.input, it.valid, FieldValidator.checkName(it.input) == null) }

    @Test fun values() =
        HttpFieldVectors.VALUES.forEach {
            expect(
                "value",
                it.input,
                it.valid,
                FieldValidator.checkValue(it.input) == null,
            )
        }

    @Test fun authorities() =
        HttpFieldVectors.AUTHORITIES.forEach {
            expect(
                "authority",
                it.input,
                it.valid,
                FieldValidator.checkAuthority(it.input, it.userinfo, it.hostRequired, it.portRequired) == null,
            )
        }

    @Test fun requests() =
        HttpFieldVectors.REQUESTS.forEach {
            expect("request", it.fields, it.valid, valid { PseudoHeaders.parseRequest(it.fields, connectProtocolEnabled = true) })
        }

    @Test fun responses() =
        HttpFieldVectors.RESPONSES.forEach { expect("response", it.fields, it.valid, valid { PseudoHeaders.parseResponse(it.fields) }) }

    @Test fun trailers() =
        HttpFieldVectors.TRAILERS.forEach {
            expect("trailers", it.fields, it.valid, valid { PseudoHeaders.parseTrailers(it.fields) })
        }
}
