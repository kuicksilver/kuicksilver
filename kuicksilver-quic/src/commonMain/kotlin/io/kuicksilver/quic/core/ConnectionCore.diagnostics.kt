// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.TlsRole

// The connection IDs each path uses, for `ConnectionInfo.paths` (docs/guide/quic.md, "Observability"). Read on the loop
// only; nothing here allocates per packet.

/**
 * Client: the server's 1-RTT packet that arrived through [socket] from [from] carried our ID at [off] in [buf]. The path of
 * that socket and that peer address keeps it (several paths can share a socket: a probe of the server's preferred address
 * leaves from the active path's); a packet of no path changes nothing. While the ID stays the same this is one comparison,
 * a new one is looked up among ours once.
 */
internal fun ConnectionCore.noteClientRxCid(
    socket: PathId,
    from: io.ktor.network.sockets.InetSocketAddress,
    buf: PacketBuffer,
    off: Int,
    len: Int,
) {
    val p = paths.byRemote(socket, from) ?: return // indexed lookup: no iterator per packet (allocation gate)
    val last = p.clientRxCid
    if (last != null && last.contentEquals(buf, off, len)) return
    val seq = cids.localSeqOf(buf, off, len)
    if (seq < 0) return // not one of ours (cannot happen once routed here): the last known stays
    p.clientRxCidSeq = seq
    p.clientRxCid = cids.localCidOf(seq)
}

/**
 * The sequence number of our ID the peer's packets on [p] carry: the latest one seen there, else, on the path the connection
 * started on, the handshake's (0); -1 when none is known yet (a new path the peer has not sent on).
 */
internal fun ConnectionCore.localCidSeqOn(p: Path): Long {
    val seen = if (role == TlsRole.Client) p.clientRxCidSeq else p.lastRxDcidSeq
    return if (seen < 0 && p.id == PathId.Initial) 0L else seen
}

/** Our ID with sequence number [seq], live or retired and still routing; null when it is gone or unknown. */
internal fun ConnectionCore.localCidBySeq(seq: Long): ConnectionId? = if (seq < 0) null else cids.localCidOf(seq)

/** The peer's ID our packets on [p] carry: the connection's current one on the active path, the path's own elsewhere. */
internal fun ConnectionCore.remoteCidOn(p: Path): ConnectionId? = if (p === paths.active) remoteCid else p.peerCid?.cid

/** The sequence number of [remoteCidOn]; -1 while the peer gave it none (its handshake ID before its transport parameters). */
internal fun ConnectionCore.remoteCidSeqOn(p: Path): Long = if (p === paths.active) cids.peerSeqOf(remoteCid) else p.peerCid?.seq ?: -1L
