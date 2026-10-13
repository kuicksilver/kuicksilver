// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.quicConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** How `quic` and `quicMaxIdleTimeout` combine into the HTTP/3 listeners' QUIC settings. */
class ServerQuicConfigTest {
    @Test fun quicMaxIdleTimeoutAppliesWhileQuicIsUnset() {
        val c = KuicksilverApplicationEngine.Configuration().apply { quicMaxIdleTimeout = 7.seconds }
        assertEquals(7.seconds, c.http3Quic().maxIdleTimeout)
    }

    /** Assigning [QuicConfig.Default] is setting `quic`: it carries its own timeout, as any other assigned value does. */
    @Test fun quicAssignedTheDefaultIsSetToo() {
        val c =
            KuicksilverApplicationEngine.Configuration().apply {
                quicMaxIdleTimeout = 7.seconds
                quic = QuicConfig.Default
            }
        assertEquals(QuicConfig.Default.maxIdleTimeout, c.http3Quic().maxIdleTimeout)
    }

    /** The order of the two assignments does not matter. */
    @Test fun quicSetBeforeOrAfterTheTimeoutWins() {
        val explicit = quicConfig { maxIdleTimeout = 20.seconds }
        val before =
            KuicksilverApplicationEngine.Configuration().apply {
                quic = explicit
                quicMaxIdleTimeout = 7.seconds
            }
        val after =
            KuicksilverApplicationEngine.Configuration().apply {
                quicMaxIdleTimeout = 7.seconds
                quic = explicit
            }
        assertEquals(20.seconds, before.http3Quic().maxIdleTimeout)
        assertEquals(20.seconds, after.http3Quic().maxIdleTimeout)
    }

    @Test fun nothingSetKeepsTheDefault() {
        assertEquals(QuicConfig.Default, KuicksilverApplicationEngine.Configuration().http3Quic())
    }
}
