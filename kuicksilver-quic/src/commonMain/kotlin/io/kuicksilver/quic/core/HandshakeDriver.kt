// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.Direction
import io.kuicksilver.tls.DriveResult
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.PacketProtector
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.VerifyResult

/** What the core does with the TLS session's output. */
internal interface HandshakeSink {
    fun onCryptoData(
        level: Int,
        data: ByteArray,
    )

    fun onKeys(
        level: Int,
        direction: Direction,
        protector: PacketProtector,
    )

    fun onPeerTransportParameters(
        encoded: ByteArray,
        negotiatedVersion: Int,
    )

    fun onHandshakeDone()

    fun onSessionTicket(ticket: io.kuicksilver.tls.QuicSessionTicket)

    fun onVerifyRequested(chain: List<Certificate>)

    fun onTlsFailure(
        exception: TlsException,
        alert: Int?,
    )
}

/** Drives [session] until it needs input, routing its events to the [sink]. */
internal class HandshakeDriver(
    val session: QuicTlsSession,
    private val sink: HandshakeSink,
) {
    private var waitingVerify = false
    var failed: Boolean = false
        private set
    var done: Boolean = false
        private set

    fun provide(
        level: Int,
        data: ByteArray,
        len: Int,
    ) {
        session.provide(EncryptionLevel.entries[level], data, 0, len)
    }

    fun drive() {
        if (failed || waitingVerify) return
        while (true) {
            val r = session.drive()
            dispatch()
            when (r) {
                is DriveResult.Failed -> {
                    failed = true
                    sink.onTlsFailure(r.exception, r.alert)
                    return
                }

                is DriveResult.WantVerify -> {
                    waitingVerify = true
                    sink.onVerifyRequested(r.chain)
                    return
                }

                DriveResult.WantRead -> {
                    return
                }

                DriveResult.Progress -> {}
            }
        }
    }

    private fun dispatch() {
        while (true) {
            when (val ev = session.nextEvent() ?: break) {
                is TlsEvent.CryptoData -> {
                    sink.onCryptoData(ev.level.ordinal, ev.data)
                }

                is TlsEvent.Keys -> {
                    sink.onKeys(ev.level.ordinal, ev.direction, ev.protector)
                }

                is TlsEvent.PeerTransportParameters -> {
                    sink.onPeerTransportParameters(ev.encoded, ev.negotiatedVersion)
                }

                TlsEvent.HandshakeDone -> {
                    done = true
                    sink.onHandshakeDone()
                }

                is TlsEvent.SessionTicket -> {
                    sink.onSessionTicket(ev.ticket)
                }
            }
        }
    }

    fun resumeVerify(result: VerifyResult) {
        if (!waitingVerify) return
        waitingVerify = false
        session.resumeVerify(result)
        drive()
    }
}
