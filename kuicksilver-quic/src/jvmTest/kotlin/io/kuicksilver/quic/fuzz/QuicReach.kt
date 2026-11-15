// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.core.ecnCeReceived
import io.kuicksilver.tls.TlsRole
import java.util.IdentityHashMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Which path, ECN, address and version features the stateful connection fuzzer reached, counted per input (a feature
 * counts once per run that reached it), shared by every run in the JVM: the seeded test asserts that its programs reach
 * each of [FEATURES], and a replay of the corpora prints the table. Read from the cores and endpoints after every round,
 * never from inside them.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal object QuicReach {
    /**
     * The features the seeded programs must reach (ConnectionSeededTest). A wait released by the client's packets with the same ID of
     * ours (`migration.waitReleased.sameId`) is counted but not required: the engine reaches it (the previous path returns its ID once
     * its re-validation after a migration succeeds, and a revert there waits), but not this harness, whose two sides share one
     * active_connection_id_limit: with small limits the client, after moving, has no unused ID of the server's left to answer the
     * server's re-validation of its old address (RFC 9000 section 9.5), so that re-validation never succeeds; with the default ones (4)
     * the server holds the client's IDs for the old and the new address and two spare, so the fallback takes a spare instead of
     * waiting, and every further client path that would spend them holds an ID of its own and becomes a fallback itself. Losing the
     * client's NEW_CONNECTION_ID (a BLOCK right after the old address's PATH_RESPONSE) does not change that: the spares are there
     * already. Only PathTest.negative_theClientsPacketsWithTheSameIdEndTheWait
     * reaches it.
     */
    val FEATURES =
        listOf(
            "pmtud.enabled",
            "pmtud.probeSent",
            "pmtud.raised",
            "pmtud.searchDone",
            "pmtud.fellBack",
            "pmtud.ptbAccepted",
            "pmtud.ptbIgnored",
            "ecn.testing",
            "ecn.capable",
            "ecn.failed",
            "ecn.ceReceived",
            "ecn.ceCongestion",
            "retry.received",
            "retry.forgedIgnored",
            "vn.received",
            "vn.versionChanged",
            "vn.compatible",
            "vn.downgradeRefused",
            "reset.sent",
            "reset.recognised",
            "reset.invalidIgnored",
            "reset.strangerIgnored",
            "preferred.offered",
            "preferred.probe",
            "preferred.moved",
            "preferred.serverMoved",
            "preferred.failed",
            "migration.clientPath",
            "migration.validated",
            "migration.rebind",
            "migration.fallback",
            "migration.reverted",
            "migration.noViablePath",
            "migration.waitReleased.newId",
            "migration.waitReleased.retirePriorTo",
            "migration.socketCapsLost",
        )

    private val counts = ConcurrentHashMap<String, AtomicLong>()
    private val runs = AtomicLong()
    private val current = ThreadLocal<HashSet<String>>()
    private val maxMtu = ThreadLocal<IdentityHashMap<ConnectionCore, Int>>()

    fun begin() {
        current.set(HashSet())
        maxMtu.set(IdentityHashMap())
    }

    fun end() {
        val s = current.get() ?: return
        current.remove()
        maxMtu.remove()
        runs.incrementAndGet()
        for (k in s) counts.computeIfAbsent(k) { AtomicLong() }.incrementAndGet()
    }

    fun hit(key: String) {
        current.get()?.add(key)
    }

    fun runs(): Long = runs.get()

    fun snapshot(): Map<String, Long> = counts.entries.associate { it.key to it.value.get() }.toSortedMap()

    fun reset() {
        counts.clear()
        runs.set(0)
    }

    /** Records what [c] shows now. */
    fun observe(c: ConnectionCore) {
        if (current.get() == null) return
        val all = c.paths.all
        var top = 0
        for (i in all.indices) {
            val p = all[i]
            if (p.pmtud != null) hit("pmtud.enabled")
            if (p.mtu > 1200) hit("pmtud.raised")
            if (p.mtu > top) top = p.mtu
            when (p.ecn.state) {
                EcnState.Testing, EcnState.Unknown -> {
                    hit("ecn.testing")
                }

                EcnState.Capable -> {
                    hit("ecn.capable")
                }

                EcnState.Failed -> {
                    hit("ecn.failed")
                }

                else -> {}
            }
        }
        val seen = maxMtu.get()
        val before = seen[c] ?: 0
        if (c.path.mtu < before) hit("pmtud.fellBack")
        if (top > before) seen[c] = top
        if (c.pmtudProbesSentForTest > 0) hit("pmtud.probeSent")
        if (c.pmtudSearchDoneForTest) hit("pmtud.searchDone")
        if (c.ecnCeReceived() > 0) hit("ecn.ceReceived")
        if (c.ecnCeEvents > 0) hit("ecn.ceCongestion")
        if (c.pathFallbacksForTest > 0) hit("migration.fallback")
        if (c.pathRevertsForTest > 0) hit("migration.reverted")
        for (w in io.kuicksilver.quic.core.WaitRelease.entries) {
            if (c.pathWaitReleasesForTest[w.ordinal] >
                0
            ) {
                hit("migration.waitReleased.${w.name.replaceFirstChar { it.lowercase() }}")
            }
        }
        if (c.role == TlsRole.Client) {
            if (c.retryReceivedForTest) hit("retry.received")
            if (c.receivedVnVersions != null) hit("vn.received")
            if (c.version != c.config.firstVersion) {
                hit("vn.versionChanged")
                if (c.receivedVnVersions == null) hit("vn.compatible")
            }
            if (c.peerTp?.preferredAddressPresent == true) hit("preferred.offered")
            if (all.any { it.preferred }) hit("preferred.probe")
            if (c.movedToPreferred) hit("preferred.moved")
            if (all.any { it.socket != io.kuicksilver.quic.PathId.Initial }) hit("migration.clientPath")
        } else {
            if (c.path.socket == PREFERRED_SOCKET) hit("preferred.serverMoved")
            if (all.size > 1) hit("migration.rebind")
        }
    }
}
