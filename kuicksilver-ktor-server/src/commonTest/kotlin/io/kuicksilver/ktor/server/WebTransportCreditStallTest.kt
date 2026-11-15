// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.WebTransportBidiStream
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.http3.WebTransportDiagnostics
import io.kuicksilver.http3.WebTransportReceiveStream
import io.kuicksilver.http3.WebTransportSendStream
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.quic.DatagramSendResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The Ktor server engine logs a draft-14 peer's credit stall (`WebTransportDiagnostics.creditStall`) once per session,
 * through the application's log ([watchCreditStall]); nothing for a session that ended first or cannot say.
 */
class WebTransportCreditStallTest {
    private class Stub(
        override val creditStall: CompletableDeferred<String> = CompletableDeferred(),
    ) : WebTransportSession,
        WebTransportDiagnostics {
        override val sessionId: Long = 0
        override val headers: Http3Headers = Http3Headers.Empty
        override val protocol: String? = null
        override val drainRequested: StateFlow<Boolean> = MutableStateFlow(false)
        override val closed: Deferred<WebTransportCloseInfo> = CompletableDeferred()

        override suspend fun openBidi(): WebTransportBidiStream = error("unused")

        override suspend fun openUni(): WebTransportSendStream = error("unused")

        override suspend fun acceptBidi(): WebTransportBidiStream = error("unused")

        override suspend fun acceptUni(): WebTransportReceiveStream = error("unused")

        override fun trySendDatagram(payload: ByteArray): DatagramSendResult = error("unused")

        override suspend fun sendDatagram(payload: ByteArray) = error("unused")

        override suspend fun receiveDatagram(): ByteArray = error("unused")

        override suspend fun drain() = error("unused")

        override suspend fun close(
            code: Long,
            reason: String,
        ) = error("unused")
    }

    @Test fun aStallIsReportedOnce() {
        val s = Stub()
        val seen = ArrayList<String>()
        watchCreditStall(s) { seen += it }
        s.creditStall.complete("stalled")
        s.creditStall.complete("again")
        assertEquals(listOf("stalled"), seen)
    }

    @Test fun negative_nothingAfterTheHandlerEnded() {
        val s = Stub()
        val seen = ArrayList<String>()
        watchCreditStall(s) { seen += it }?.dispose()
        s.creditStall.complete("stalled")
        assertEquals(emptyList(), seen)
    }

    @Test fun negative_aSessionThatCannotSayIsNotWatched() {
        val plain = object : WebTransportSession by Stub() {}
        assertNull(watchCreditStall(plain) { error("not reported") })
    }
}
