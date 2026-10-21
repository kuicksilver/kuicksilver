// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Endpoint.Companion.forHttp3Server
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The QUIC configuration an HTTP/3 server runs with. A request stream the QUIC layer gives up without the server ever seeing it
 * (one whose acceptor was cancelled) is reset with `QuicConfig.defaultStreamErrorCode`; QUIC's default 0 is no HTTP/3 code (a
 * client reads it as H3_NO_ERROR, RFC 9114 section 9), so the server uses H3_REQUEST_REJECTED, which tells the client the
 * request was not processed and may be retried (sections 4.1.1 and 8.1).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class Http3ServerQuicConfigTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun endpoint(
        code: Long?,
        early: Boolean = false,
    ) = QuicEndpointConfig
        .Builder()
        .apply {
            server =
                QuicServerConfig
                    .Builder(H3Fixtures.server())
                    .apply {
                        quic =
                            quicConfig {
                                maxBidiStreams = 7
                                code?.let { defaultStreamErrorCode = it }
                            }
                        earlyData = early
                    }.build()
            crypto = NullCryptoProvider
        }.build()

    @Test fun aRequestStreamAbandonedUnseenIsRejected() {
        val q = endpoint(null).forHttp3Server(Http3Settings.Default).server!!.quic
        assertEquals(Http3ErrorCode.REQUEST_REJECTED, q.defaultStreamErrorCode)
        assertEquals(7L, q.maxBidiStreams, "the rest of the configuration is kept")
    }

    @Test fun aCodeSetExplicitlyIsKept() {
        val q = endpoint(Http3ErrorCode.INTERNAL_ERROR).forHttp3Server(Http3Settings.Default).server!!.quic
        assertEquals(Http3ErrorCode.INTERNAL_ERROR, q.defaultStreamErrorCode)
    }

    @Test fun aZeroRttServerKeepsItsEarlyDataAndTheRejectionCode() {
        val s = endpoint(null, early = true).forHttp3Server(Http3Settings.Default).server!!
        assertTrue(s.earlyData)
        assertEquals(Http3ErrorCode.REQUEST_REJECTED, s.quic.defaultStreamErrorCode)
    }

    @Test fun aClientOnlyEndpointIsUnchanged() {
        val c = QuicEndpointConfig.Builder().apply { crypto = NullCryptoProvider }.build()
        assertNull(c.forHttp3Server(Http3Settings.Default).server)
    }
}
