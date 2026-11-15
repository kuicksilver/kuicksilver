// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.message.PseudoHeaders
import io.kuicksilver.http3.qpack.entrySize
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** The peer's SETTINGS_MAX_FIELD_SECTION_SIZE at its exact value. */
class FieldLimitGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * RFC 9114 section 4.2.2: "An implementation that has received this parameter SHOULD NOT send an HTTP message header
     * that exceeds the indicated size"; the size is "the uncompressed size of fields, including the length of the name and
     * value in bytes plus an overhead of 32 bytes for each field". A section of exactly the limit does not exceed it and is
     * sent; one byte more is refused before a stream opens.
     */
    @Test fun negative_requestOfExactlyThePeersLimitIsSent() =
        h3Test {
            val req = get(headers = Http3Headers.of("x-pad" to "v".repeat(100)))
            val size = PseudoHeaders.buildRequest(req).sumOf { entrySize(it.first, it.second) }
            H3Pair.open(serverSettings = http3Settings { maxFieldSectionSize = size }).useScoped { p ->
                withTimeout(5.seconds) { p.client.peerSettings.first { it != null } }
                val served =
                    async {
                        p.server
                            .acceptRequest()
                            .respond(204)
                            .finish()
                    }
                assertEquals(204, p.client.request(req).status)
                served.await()
            }
            H3Pair.open(serverSettings = http3Settings { maxFieldSectionSize = size - 1 }).useScoped { p ->
                withTimeout(5.seconds) { p.client.peerSettings.first { it != null } }
                assertFailsWith<Http3Exception.FieldSectionTooLarge> { p.client.request(req) }
            }
        }
}
