// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TrackingCrypto
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** An [EndpointCore] whose construction fails frees what it had already allocated: on Kotlin/Native nothing else would. */
@OptIn(ExperimentalKuicksilverApi::class)
class EndpointCoreConstructionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun serverConfig(crypto: TrackingCrypto) =
        QuicEndpointConfig
            .Builder()
            .apply {
                server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                this.crypto = crypto
            }.build()

    @Test fun aFailureAfterTheResetKeyClosesIt() {
        val crypto = TrackingCrypto(failTokenKey = true) // the address tokens come after the stateless buffer and the reset key
        assertFailsWith<IllegalStateException> { EndpointCore(serverConfig(crypto), Random(1)) }
        assertEquals(1, crypto.closed, "the reset key made before the failure")
        assertEquals(0, crypto.live)
    }

    @Test fun closedSharedTokensLeaveNothingAllocated() {
        val crypto = TrackingCrypto()
        val tokens = AddressTokens(crypto, Random(2))
        tokens.close() // a group's keys already released: the loop cannot take a reference
        assertFailsWith<IllegalStateException> { EndpointCore(serverConfig(crypto), Random(3), 0, tokens) }
        assertEquals(0, crypto.live, "the reset key and the group's keys")
    }

    @Test fun aWorkingEndpointClosesEveryKey() {
        val crypto = TrackingCrypto()
        EndpointCore(serverConfig(crypto), Random(4)).close()
        assertEquals(0, crypto.live)
    }

    @Test fun addressTokensWhoseSecondKeyFailsCloseTheFirst() {
        val crypto = TrackingCrypto(tokenKeys = 1) // the Retry key is made, the NEW_TOKEN key is refused
        assertFailsWith<IllegalStateException> { AddressTokens(crypto, Random(5)) }
        assertEquals(1, crypto.made)
        assertEquals(0, crypto.live, "the Retry key")
    }
}
