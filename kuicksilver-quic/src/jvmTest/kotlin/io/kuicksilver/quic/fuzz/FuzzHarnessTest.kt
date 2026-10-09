// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** EndpointCore turns a crash inside a connection into ConnectionLost.Internal; the endpoint fuzz targets must still see it as a finding. */
@OptIn(ExperimentalKuicksilverApi::class)
class FuzzHarnessTest {
    @Test fun internalFailureOfAServerConnectionFailsTheTarget() {
        CoreDriver().use { d ->
            val ep = d.serverEndpoint()
            val c = d.client()
            var rounds = 0
            while (c.state != ConnectionState.Confirmed && rounds++ < 100) {
                for (dg in d.service(c)) d.deliver(ep, dg, fuzzClientAddr)
                for (s in ep.connections().toList()) for (dg in d.service(s)) d.deliver(c, dg, fuzzServerAddr)
                d.tick(5)
            }
            assertEquals(ConnectionState.Confirmed, c.state)
            ep.connections().single().testInjectFailure = IllegalStateException("injected crash")
            val e =
                assertFailsWith<IllegalStateException> {
                    d.deliver(
                        ep,
                        ByteArray(40) { 0x40 }.also { b ->
                            ep
                                .connections()
                                .single()
                                .localCid
                                .toByteArray()
                                .copyInto(b, 1)
                        },
                        fuzzClientAddr,
                    )
                    d.service(ep)
                }
            assertEquals(
                "injected crash",
                generateSequence<Throwable>(e) { it.cause }.last().message,
                "the finding carries the original exception",
            )
        }
    }
}
