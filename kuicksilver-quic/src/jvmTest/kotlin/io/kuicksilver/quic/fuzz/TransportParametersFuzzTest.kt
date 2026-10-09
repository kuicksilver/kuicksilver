// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.TransportParameters
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.tls.TlsRole

/**
 * Fuzz target `transportParameters`: input = [sender selector][encoded parameters]. A decoded set must re-encode
 * and decode to the same values.
 */
class TransportParametersFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun transportParameters(data: ByteArray) {
        if (data.isEmpty()) return
        KslLoader.ensureLoaded()
        val sender = if (data[0].toInt() and 1 == 0) TlsRole.Client else TlsRole.Server
        val tp =
            try {
                TransportParametersCodec.decode(data.copyOfRange(1, data.size), sender)
            } catch (_: QuicWireException) {
                return
            }
        if (data.size > 900) return // encode() writes our own parameters into 1 KiB; a long peer version list need not fit
        val again = TransportParametersCodec.decode(TransportParametersCodec.encode(tp, sender, 27), sender)
        check(render(tp) == render(again)) { "round trip changed the parameters:\n${render(tp)}\n${render(again)}" }
    }

    private fun render(tp: TransportParameters): String =
        listOf(
            tp.originalDestinationConnectionId,
            tp.maxIdleTimeoutMs,
            tp.statelessResetToken?.toList(),
            tp.maxUdpPayloadSize,
            tp.initialMaxData,
            tp.initialMaxStreamDataBidiLocal,
            tp.initialMaxStreamDataBidiRemote,
            tp.initialMaxStreamDataUni,
            tp.initialMaxStreamsBidi,
            tp.initialMaxStreamsUni,
            tp.ackDelayExponent,
            tp.maxAckDelayMs,
            tp.disableActiveMigration,
            tp.preferredAddressPresent,
            tp.activeConnectionIdLimit,
            tp.initialSourceConnectionId,
            tp.retrySourceConnectionId,
            tp.maxDatagramFrameSize,
            tp.greaseQuicBit,
            tp.chosenVersion,
            tp.availableVersions?.toList(),
        ).joinToString()
}
