// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.PacketProtector
import kotlin.time.Duration

/**
 * The 1-RTT key phases of a connection (RFC 9001 section 6). The next generation's keys are derived the moment the
 * current ones are installed (section 9.5: no timing side channel on whether a new-phase packet arrived); the previous
 * generation's read key stays until a packet of the new phase authenticated and 3 x PTO after that (section 6.1: "MUST
 * retain old keys until it has successfully unprotected a packet sent using the new keys"), so reordered packets still
 * decrypt; header protection uses the generation-0 protector, whose HP key every generation shares (section 5.4).
 */
internal class KeyPhase(
    read: PacketProtector,
    write: PacketProtector,
    private val onChange: (read: PacketProtector, write: PacketProtector) -> Unit,
) : AutoCloseable {
    /** The Key Phase bit of packets we send now. */
    var phase: Boolean = false
        private set
    var generation: Long = 0
        private set

    /** Header protection for received packets: the generation-0 read protector (same HP key for every generation). */
    val hpRead: PacketProtector = read
    private val hpWrite: PacketProtector = write
    var read: PacketProtector = read
        private set
    var write: PacketProtector = write
        private set
    private var nextRead: PacketProtector = read.next()
    private var nextWrite: PacketProtector = write.next()
    private var previous: PacketProtector? = null

    /** When the previous generation's read key is dropped; [TimeMark.NEVER] when there is none or no new-phase packet arrived yet. */
    var discardAt: TimeMark = TimeMark.NEVER
        private set
    private var firstPnOfCurrent = Long.MAX_VALUE // lowest packet number received in the current phase
    private var firstPnSentInCurrent = Long.MAX_VALUE // our first packet of the current phase

    /** When the peer first acknowledged a packet of the current phase (RFC 9001 section 6.5); [TimeMark.NEVER] until then. */
    var confirmedAt: TimeMark = TimeMark.NEVER
        private set
    private var ackedInCurrent = false // the peer acknowledged one of our packets of the current phase (section 6.1, our own next update)

    // we acknowledged a packet of the peer's current phase: only then may the peer update again (section 6.1 seen from the responder)
    private var ackSentForCurrentPhase = false

    /** Packets sealed with the current write key (the AEAD confidentiality limit, RFC 9001 section 6.6, counts these). */
    var packetsProtected: Long = 0
        private set

    /** Key updates so far, ours and the peer's. */
    var updates: Long = 0
        private set

    /** The read key for a packet with [phaseBit] and [pn], or null when no key can apply (an old phase whose keys are gone). */
    fun readKey(
        phaseBit: Boolean,
        pn: Long,
    ): PacketProtector? {
        if (phaseBit == phase) return read
        if (pn < firstPnOfCurrent) previous?.let { return it }
        return nextRead // a candidate update by the peer (or, below the current phase with no previous keys: must fail to authenticate)
    }

    /** A packet authenticated with [readKey]'s choice: commits a peer-initiated update; the two RFC 9001 section 6 violations are KEY_UPDATE_ERROR. */
    fun onAuthenticated(
        phaseBit: Boolean,
        pn: Long,
        now: TimeMark,
        pto: Duration,
    ) {
        if (phaseBit == phase) {
            // the first packet of a phase we initiated: the peer has the new keys, so the old ones go 3 x PTO from now
            if (firstPnOfCurrent == Long.MAX_VALUE && previous != null && discardAt == TimeMark.NEVER) discardAt = now + pto * 3
            if (pn < firstPnOfCurrent) firstPnOfCurrent = pn
            return
        }
        if (pn < firstPnOfCurrent) {
            if (previous != null) return // a reordered packet of the previous phase
            throw QuicWireException(
                TransportError.KEY_UPDATE_ERROR,
                0,
                "new key phase with a packet number below the current phase (RFC 9001 section 6.4)",
            )
        }
        if (generation > 0 &&
            !ackSentForCurrentPhase
        ) {
            throw QuicWireException(
                TransportError.KEY_UPDATE_ERROR,
                0,
                "consecutive key update before we acknowledged any packet of the current phase (RFC 9001 section 6.1)",
            )
        }
        flip(now + pto * 3)
        firstPnOfCurrent = pn
    }

    /**
     * Section 6.1: the handshake is confirmed; a *subsequent* update also needs an acknowledgment of a packet of the current
     * phase, and (section 6.5, SHOULD) 3 x PTO since that acknowledgment, while the peer may still hold its old keys.
     */
    fun canInitiate(
        handshakeConfirmed: Boolean,
        now: TimeMark,
        pto: Duration,
    ): Boolean = handshakeConfirmed && (generation == 0L || (ackedInCurrent && now >= confirmedAt + pto * 3))

    /** When [canInitiate] turns true for a confirmed connection, or [TimeMark.NEVER] while it waits for an acknowledgment. */
    fun initiateAllowedAt(pto: Duration): TimeMark = if (generation == 0L || !ackedInCurrent) TimeMark.NEVER else confirmedAt + pto * 3

    fun initiate(
        now: TimeMark,
        pto: Duration,
    ): Boolean {
        if (!canInitiate(true, now, pto)) return false
        flip(TimeMark.NEVER) // the old read key stays until the peer's first packet of the new phase (onAuthenticated)
        return true
    }

    fun onPacketSent(pn: Long) {
        if (firstPnSentInCurrent == Long.MAX_VALUE) firstPnSentInCurrent = pn
        packetsProtected++
    }

    fun onPacketAcked(
        pn: Long,
        now: TimeMark,
    ) {
        if (pn >= firstPnSentInCurrent && !ackedInCurrent) {
            ackedInCurrent = true
            confirmedAt = now
        }
    }

    /** We sent an ACK frame in the 1-RTT space; it covers every unacknowledged packet, so a received packet of the current phase is now acknowledged. */
    fun onAckSent() {
        if (firstPnOfCurrent != Long.MAX_VALUE) ackSentForCurrentPhase = true
    }

    /** Drops the previous generation's read key once its window passed. */
    fun onTimeout(now: TimeMark) {
        if (previous != null &&
            now >= discardAt
        ) {
            closeUnlessHp(previous!!)
            previous = null
            discardAt = TimeMark.NEVER
        }
    }

    private fun flip(discardPreviousAt: TimeMark) {
        previous?.let { closeUnlessHp(it) }
        previous = read
        read = nextRead
        closeUnlessHp(write)
        write = nextWrite
        nextRead = read.next()
        nextWrite = write.next()
        phase = !phase
        generation++
        updates++
        discardAt = discardPreviousAt
        firstPnOfCurrent = Long.MAX_VALUE
        firstPnSentInCurrent = Long.MAX_VALUE
        ackedInCurrent = false
        confirmedAt = TimeMark.NEVER
        ackSentForCurrentPhase = false
        packetsProtected =
            0
        onChange(read, write)
    }

    private fun closeUnlessHp(p: PacketProtector) {
        if (p !== hpRead && p !== hpWrite) p.close()
    }

    override fun close() {
        previous?.let { closeUnlessHp(it) }
        previous = null
        closeUnlessHp(read)
        closeUnlessHp(write)
        closeUnlessHp(nextRead)
        closeUnlessHp(nextWrite)
        hpRead.close()
        hpWrite.close()
    }
}
