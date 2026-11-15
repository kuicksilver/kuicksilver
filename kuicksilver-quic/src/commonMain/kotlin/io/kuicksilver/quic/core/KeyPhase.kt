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
 * decrypt; header protection uses the generation-0 protector, whose HP key every generation shares (section 5.4). Every packet
 * number opened with a generation is above every packet number opened with an older one (section 6.4), whichever arrives first.
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

    // RFC 9001 section 6.4: "Packets with higher packet numbers MUST be protected with either the same or newer packet protection keys
    // than packets with lower packet numbers." Every packet number opened with one generation is above every one opened with an older
    // generation, checked in both orders of arrival against these bounds:
    private var minCurrent = Long.MAX_VALUE // lowest packet number opened with the current read key (none: MAX_VALUE)
    private var maxCurrent = -1L // highest packet number opened with the current read key (none: -1)
    private var maxBelowCurrent = -1L // highest packet number opened with any older generation (the previous one included)
    private var maxBelowPrevious = -1L // highest packet number opened with a generation older than the previous one
    private var firstPnSentInCurrent = Long.MAX_VALUE // our first packet of the current phase

    /** The last packet [onAuthenticated] took was opened with the previous generation's key (section 6.2, [checkAckInPacket]). */
    private var openedWithPrevious = false

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

    /**
     * Section 6.5: the Key Phase bit of the current phase selects the current key; the other value selects the previous key for a
     * packet number below every one of the current phase (while that key is kept) and the next key otherwise. The choice depends
     * only on the bit and the packet number, never on whether a key was derived on demand (section 9.5: every key exists already).
     */
    private fun choose(
        phaseBit: Boolean,
        pn: Long,
    ): Int =
        when {
            phaseBit == phase -> CURRENT
            previous != null && pn < minCurrent -> PREVIOUS
            else -> NEXT
        }

    /** The read key for a packet with [phaseBit] and [pn]; one always applies (a key that cannot be right fails to authenticate). */
    fun readKey(
        phaseBit: Boolean,
        pn: Long,
    ): PacketProtector =
        when (choose(phaseBit, pn)) {
            CURRENT -> read
            PREVIOUS -> previous!!
            else -> nextRead
        }

    /**
     * A packet authenticated with [readKey]'s choice: commits a peer-initiated update. KEY_UPDATE_ERROR when keys and packet numbers
     * disagree (section 6.4, either order of arrival) and for a second peer update we did not acknowledge (section 6.2's MAY).
     */
    fun onAuthenticated(
        phaseBit: Boolean,
        pn: Long,
        now: TimeMark,
        pto: Duration,
    ) {
        when (choose(phaseBit, pn)) {
            CURRENT -> {
                // newer keys below a packet number opened with older keys (section 6.4); equal, a packet number used under two keys
                // (RFC 9000 section 12.3: "MUST NOT reuse a packet number")
                if (pn <= maxBelowCurrent) misordered()
                // the first packet of a phase we initiated: the peer has the new keys, so the old ones go 3 x PTO from now (section 6.5)
                if (minCurrent == Long.MAX_VALUE && previous != null && discardAt == TimeMark.NEVER) discardAt = now + pto * 3
                if (pn < minCurrent) minCurrent = pn
                if (pn > maxCurrent) maxCurrent = pn
                openedWithPrevious = false
            }

            PREVIOUS -> {
                // below every current-phase packet number (the choice); also above all the generations before it
                if (pn <= maxBelowPrevious) misordered()
                if (pn > maxBelowCurrent) maxBelowCurrent = pn
                openedWithPrevious = true
            }

            else -> {
                // the next key opened a packet number below one an older key opened: section 6.4, the order the RFC words; equal, a
                // packet number reused under another key (RFC 9000 section 12.3)
                if (pn <= maxCurrent || pn <= maxBelowCurrent) misordered()
                if (generation > 0 && !ackSentForCurrentPhase) {
                    throw QuicWireException(
                        TransportError.KEY_UPDATE_ERROR,
                        0,
                        "consecutive key update before we acknowledged any packet of the current phase (RFC 9001 section 6.2)",
                    )
                }
                flip(now + pto * 3)
                minCurrent = pn
                maxCurrent = pn
                openedWithPrevious = false
            }
        }
    }

    private fun misordered(): Nothing =
        throw QuicWireException(
            TransportError.KEY_UPDATE_ERROR,
            0,
            "older packet protection keys on a higher packet number than newer keys (RFC 9001 section 6.4), or one packet number " +
                "under two keys (RFC 9000 section 12.3)",
        )

    /**
     * Section 6.2: "An endpoint that receives an acknowledgment that is carried in a packet protected with old keys where any
     * acknowledged packet was protected with newer keys MAY treat that as a connection error of type KEY_UPDATE_ERROR": the peer
     * acknowledged a packet that carried an update without updating. [largestAcked] is the ACK frame's Largest Acknowledged, in a
     * 1-RTT packet that [onAuthenticated] just took.
     */
    fun checkAckInPacket(
        largestAcked: Long,
        frameType: Long,
    ) {
        if (openedWithPrevious && largestAcked >= firstPnSentInCurrent) {
            throw QuicWireException(
                TransportError.KEY_UPDATE_ERROR,
                frameType,
                "acknowledgment of a new-phase packet in a packet protected with old keys (RFC 9001 section 6.2)",
            )
        }
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
        if (minCurrent != Long.MAX_VALUE) ackSentForCurrentPhase = true
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
        // the current generation becomes the previous one: what it opened joins the older generations' bound
        maxBelowPrevious = maxBelowCurrent
        if (maxCurrent > maxBelowCurrent) maxBelowCurrent = maxCurrent
        minCurrent = Long.MAX_VALUE
        maxCurrent = -1
        firstPnSentInCurrent = Long.MAX_VALUE
        ackedInCurrent = false
        confirmedAt = TimeMark.NEVER
        ackSentForCurrentPhase = false
        packetsProtected =
            0
        onChange(read, write)
    }

    private companion object {
        const val CURRENT = 0
        const val PREVIOUS = 1
        const val NEXT = 2
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
