// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.ConnectTimeoutException
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.ktor.client.h3.H3NotSent
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** [classifyH3Failure], one branch per test, and the log line of [ProtocolDiagnostics]; no network. */
class ProtocolDiagnosticsTest {
    private fun closed(
        code: Long,
        initiator: Initiator = Initiator.Peer,
    ) = QuicException.ConnectionLost.TransportClosed(code, 0, "", ByteArray(0), initiator)

    @Test fun handshakeTimeoutIsHandshakeTimeout() {
        assertEquals(
            FallbackReason.HandshakeTimeout,
            classifyH3Failure(QuicException.ConnectionLost.Timeout(TimeoutKind.Handshake, 1.seconds)),
        )
        assertEquals(FallbackReason.Http3Error, classifyH3Failure(QuicException.ConnectionLost.Timeout(TimeoutKind.Idle, 1.seconds)))
    }

    @Test fun connectTimeoutIsHandshakeTimeout() {
        assertEquals(FallbackReason.HandshakeTimeout, classifyH3Failure(ConnectTimeoutException("https://a.test", 10, null)))
    }

    @Test fun tlsAlertIsTlsFailure() {
        assertEquals(FallbackReason.TlsFailure, classifyH3Failure(closed(0x0178)))
        assertEquals(FallbackReason.TlsFailure, classifyH3Failure(closed(0x012a, Initiator.Local)))
        assertEquals(FallbackReason.Refused, classifyH3Failure(closed(0x2)))
        assertEquals(FallbackReason.Http3Error, classifyH3Failure(closed(0xa, Initiator.Local)))
    }

    @Test fun versionNegotiationIsRefused() {
        assertEquals(
            FallbackReason.Refused,
            classifyH3Failure(QuicException.ConnectionLost.VersionNegotiation(listOf(0x6b3343cf), listOf(1))),
        )
    }

    @Test fun statelessResetIsHttp3Error() {
        assertEquals(FallbackReason.Http3Error, classifyH3Failure(QuicException.ConnectionLost.StatelessReset()))
        assertEquals(FallbackReason.Http3Error, classifyH3Failure(QuicException.ConnectionLost.NoViablePath()))
        assertEquals(FallbackReason.Http3Error, classifyH3Failure(Http3Exception.Qpack(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED)))
        assertEquals(FallbackReason.Http3Error, classifyH3Failure(Http3Exception.Settings("no")))
        assertEquals(
            FallbackReason.Http3Error,
            classifyH3Failure(Http3Exception.Protocol(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, Initiator.Peer, null)),
        )
    }

    @Test fun zeroRttRejected() {
        assertEquals(FallbackReason.ZeroRttRejected, classifyH3Failure(QuicException.ConnectionLost.ZeroRttRejected()))
    }

    @Test fun h3NotSentUnwrapsCause() {
        assertEquals(
            FallbackReason.HandshakeTimeout,
            classifyH3Failure(H3NotSent(QuicException.ConnectionLost.Timeout(TimeoutKind.Handshake, 1.seconds))),
        )
    }

    @Test fun requestNotProcessedIsGoAway() {
        assertEquals(FallbackReason.GoAway, classifyH3Failure(H3NotSent(Http3Exception.RequestNotProcessed())))
    }

    @Test fun streamResetIsStreamFailed() {
        assertEquals(FallbackReason.StreamFailed, classifyH3Failure(QuicException.StreamError.Reset(0, 0x102, Initiator.Peer)))
        assertEquals(
            FallbackReason.StreamFailed,
            classifyH3Failure(Http3Exception.Protocol(Http3ErrorCode.INTERNAL_ERROR, Initiator.Peer, 0)),
        )
        assertEquals(FallbackReason.StreamFailed, classifyH3Failure(Http3Exception.MessageError(0, "bad")))
    }

    @Test fun unknownIsOther() {
        assertEquals(FallbackReason.Other, classifyH3Failure(IllegalStateException("x")))
    }

    @Test fun nullIsNotReady() {
        assertNull(classifyH3Failure(null))
    }

    /** The line names scheme, host, port and path, the fallback and the race; never the query or the user info. */
    @Test fun negative_diagnosticsLogHasNoQuery() {
        val d =
            ProtocolDiagnostics().apply {
                protocol = HttpProtocolVersion.HTTP_1_1
                reason = ProtocolReason.Race
                fallback = FallbackReason.HandshakeTimeout
                h3Failure = QuicException.ConnectionLost.TransportClosed(0x2, 0, "secret-reason", ByteArray(0), Initiator.Peer)
                alternative("example.com", 443, AlternativeSource.AltSvc)
                raced(10.milliseconds)
                markedBroken = true
            }
        val line = d.line("GET", Url("https://user:password@example.com:8443/a/b?token=secret#frag"))
        assertEquals(
            "kuicksilver: GET https://example.com:8443/a/b -> HTTP/1.1 (fallback=HandshakeTimeout, alt=example.com:443 via AltSvc, " +
                "raced, headStart=10ms, h3Failure=TransportClosed, marked broken)",
            line,
        )
        for (secret in listOf("token", "secret", "user", "password", "frag")) assertFalse(secret in line, "$secret in $line")
    }

    @Test fun h3LineIsShortAndDefaultPortIsLeftOut() {
        val d =
            ProtocolDiagnostics().apply {
                protocol = HttpProtocolVersion.HTTP_3_0
                alternative("::1", 443, AlternativeSource.Preferred)
            }
        assertEquals("kuicksilver: GET https://[::1]/ -> HTTP/3.0 (alt=[::1]:443 via Preferred)", d.line("GET", Url("https://[::1]")))
        assertNull(d.headStart)
        assertTrue(d.toString().startsWith("HTTP/3.0"))
    }

    /** A host that could end or forge a field of the line is written with `?` in place of the dangerous characters. */
    @Test fun negative_logLineEscapesHostCharacters() {
        val d = ProtocolDiagnostics().apply { alternative("x),fallback=Other", 443, AlternativeSource.AltSvc) }
        val line = d.line("GET", Url("https://example.com/"))
        assertEquals("kuicksilver: GET https://example.com/ -> HTTP/1.1 (alt=x??fallback?Other:443 via AltSvc)", line)
    }
}
