// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic.core

import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.stream.Reassembler

// Memory accounting of one connection.

/**
 * Fuzzing probe: the sizes of the per-connection collections a peer can make grow, by name (the stateful fuzzer checks
 * them against bounds derived from the configuration).
 */
internal fun ConnectionCore.sizesForTest(): Map<String, Long> {
    val m = LinkedHashMap<String, Long>()
    m["events"] = events.size.toLong()
    val st = streams.sizesForTest()
    m["streams"] = st[0].toLong()
    m["streamControlFrames"] = st[1].toLong()
    m["streamEvents"] = st[2].toLong()
    m["streamSendLimits"] = st[3].toLong()
    m["streamsEarly"] = st[4].toLong()
    m["streamsHeldFor0Rtt"] = st[5].toLong()
    m["reassemblyRanges"] = streams.reassemblyRanges.toLong()
    m["sendBufferedBytes"] = streams.sendBufferedBytes
    val ci = cids.sizesForTest()
    m["cidsLocal"] = ci[0].toLong()
    m["cidsPeer"] = ci[1].toLong()
    m["cidsRetiredLocal"] = ci[2].toLong()
    m["cidsRetiredUntil"] = ci[3].toLong()
    m["cidsPendingRetire"] = ci[4].toLong()
    m["cidsUnackedRetire"] = ci[5].toLong()
    m["paths"] = paths.all.size.toLong()
    m["pathResponses"] = paths.responses.toLong()
    for (space in io.kuicksilver.quic.recovery.SpaceId.entries) {
        val sp = loss.space(space)
        m["sent${space.name}"] = sp.sent.size.toLong()
        m["ackRanges${space.name}"] = sp.ack.rangeCount.toLong()
    }
    m["receiverBufferedBytes"] = receiver.bufferedBytes
    m["cryptoBufferedBytes"] = cryptoStreams.bufferedBytes
    m["datagramsQueued"] = datagramQueue.size.toLong()
    m["challengedAddresses"] = challengedAddressesForTest.size.toLong()
    m["mtuUpdates"] = ccMtuUpdatesForTest.size.toLong()
    m["zeroRttHeld"] = zeroRttHeldForTest().toLong()
    return m
}

// the receive term is what the reassembly buffers may hold allocated (RangeBudget): the connection window unread, as much again
// kept after reads, the doubling slack on what is unread, and the smallest buffer of each stream the peer may open
internal fun ConnectionCore.memoryCeiling(): Long =
    3L * config.maxConnectionWindow + Reassembler.MIN_WINDOW.toLong() * (config.maxBidiStreams + config.maxUniStreams) +
        config.maxSendBuffer +
        3L * config.limits.cryptoOutOfOrderPerLevel + config.limits.cryptoPostHandshake +
        config.limits.undecryptablePackets.toLong() * path.mtu + config.limits.qlogBytes
