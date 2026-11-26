// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.DatagramSender
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * The send side of the datagram API: callers from any thread hand copies over through per-group admission channels and
 * atomic counters (so `trySendDatagram` never enters the loop); the loop applies the policies, keeps the queue within
 * [maxCount] / [maxBytes], and feeds the core as its [DatagramSender]. Nothing here is retransmitted (RFC 9221).
 *
 * **Groups.** A datagram may belong to a [group][Cmd.group] (an HTTP request stream's id, so a WebTransport session:
 * [io.kuicksilver.quic.trySendDatagram] with a group); the others are of [NO_GROUP]. Fairness between groups holds at every
 * step a datagram goes through (draft-ietf-webtrans-http3-16 sections 3.4 and 8, unchanged in -17 per the project's notes):
 * - admission: every group has an admission channel of its own ([Admission]: [maxCount] commands, DROP_OLDEST), made when
 *   the group starts ([startGroup], the request stream's start; at its first datagram otherwise) and removed when it ends
 *   ([endGroup]); datagrams of no group share one. A caller that outruns the loop drops its own group's oldest command,
 *   never another group's: no two groups ever share admission. The loop drains the channels in turn;
 * - the queue: per urgency ([Cmd.urgency], -1 and RFC 9218's 0..7; the most urgent first, so a datagram never waits behind a
 *   less urgent one) each group is one flow, a FIFO of its own, and the flows take turns by deficit round robin over bytes
 *   ([QUANTUM] a turn), so a group of large datagrams gets no larger share; order is kept within a flow, which is all RFC
 *   9221 asks. One [onTransmit] writes datagrams of one urgency only, the one [nextUrgency] announced to the packet builder;
 * - eviction: a full queue makes room from the group that holds the most bytes (the sender's own on a tie), so a burst
 *   evicts its own datagrams, not those of a group that holds less; within the sender's own group only from a flow of the
 *   same or a lower urgency (a more urgent queued datagram is never dropped for a less urgent new one: the new one is dropped
 *   instead), and from another group its least urgent flow's oldest.
 *
 * LatestWins replaces a queued datagram of the same group and key only. Admission holds at most [maxCount] datagrams per
 * group on top of the queue and the one waiting for room. [DatagramPolicy.Reject] callers checked [hasRoom] (fewer than
 * [maxCount] buffered in all), so they alone never overflow a channel.
 *
 * Allocation per datagram: the [Cmd] besides the datagram's copy, and the admission channel's buffer cells (kotlinx
 * channels allocate a segment per 32 sends: amortized). The admission table is an immutable sorted snapshot swapped by
 * compare-and-set when a group starts or ends, so a send looks its channel up by binary search without a lock or an
 * allocation; a group's loop-side state and flows live until the group ends and are looked up in a map of primitive keys
 * ([LongMap]).
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
internal class DatagramSendQueue(
    private val maxCount: Int,
    private val maxBytes: Long,
) : DatagramSender {
    internal class Cmd(
        val data: ByteArray,
        val policy: DatagramPolicy,
        /** RFC 9218 urgency for scheduling against stream data ([DatagramSender.nextUrgency]); -1: ahead of every stream. */
        val urgency: Int = -1,
        /** The flow it belongs to (an HTTP request stream's id); [NO_GROUP] for datagrams of no group. */
        val group: Long = NO_GROUP,
    ) {
        /** Arrival order (loop only): eviction drops a flow's oldest. */
        var seq = 0L
    }

    /** One group's admission: a bounded channel whose overflow drops (and releases) the group's own oldest command. */
    internal class Admission(
        val group: Long,
    ) {
        lateinit var channel: Channel<Cmd>

        /** Commands sent and not yet received or dropped (counted before the send, so never short). */
        val held = AtomicInt(0)

        /** 1 once its group's start was reported ([startGroup]): never swept, only [endGroup] removes it. */
        val registered = AtomicInt(0)
    }

    /** The registered groups' admissions, sorted by group (an immutable snapshot: replaced, never changed). */
    private class Table(
        val groups: LongArray,
        val admissions: Array<Admission>,
    ) {
        /** [group]'s index, or -(insertion point + 1) when it has none (binary search: no allocation). */
        fun indexOf(group: Long): Int {
            var lo = 0
            var hi = groups.size - 1
            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                val g = groups[mid]
                when {
                    g < group -> lo = mid + 1
                    g > group -> hi = mid - 1
                    else -> return mid
                }
            }
            return -(lo + 1)
        }

        fun find(group: Long): Admission? = indexOf(group).let { if (it >= 0) admissions[it] else null }
    }

    private fun newAdmission(group: Long) =
        Admission(group).also { a ->
            a.channel =
                Channel(maxCount, BufferOverflow.DROP_OLDEST) {
                    a.held.decrementAndFetch()
                    release(it)
                }
        }

    /** Set by [close]: later sends are dropped at once. */
    private val closed = AtomicInt(0)

    private val table = AtomicReference(Table(LongArray(0), emptyArray()))

    /** The admission of datagrams of no group. */
    private val shared = newAdmission(NO_GROUP)

    /** Loop only: admissions of ended groups, drained until empty. */
    private val closing = ArrayList<Admission>()

    /** Loop only: where the next drain round starts (the channels take turns). */
    private var nextSource = 0

    /** Wakes the loop-side drainer once per burst. */
    val signal = Channel<Unit>(Channel.CONFLATED)

    /** Datagrams admitted and not yet sent or dropped, as seen from any thread (for Reject); the loop keeps them exact. */
    val count = AtomicInt(0)
    val bytes = AtomicLong(0)

    /** One group's datagrams of one urgency, in arrival order; kept with its group. */
    private class Flow(
        val group: Group,
        val index: Int,
    ) {
        val fifo = ArrayDeque<Cmd>()
        var deficit = 0
        var inRing = false
    }

    /** A group's state: its flows per urgency index, its queued bytes, whether its stream ended. */
    private class Group(
        val id: Long,
    ) {
        val flows = arrayOfNulls<Flow>(URGENCIES)
        var queuedBytes = 0L
        var queuedCount = 0
        var ended = false

        /** Its place in [active] while it has datagrams queued, -1 otherwise. */
        var activeIndex = -1
    }

    private val groups = LongMap<Group>()

    /** The groups with datagrams queued (eviction looks only at these). */
    private val active = ArrayList<Group>()

    /** Per urgency index: the flows with datagrams, in turn order; [nonEmpty] has bit i set while ring i has one. */
    private val rings = Array(URGENCIES) { ArrayDeque<Flow>() }
    private var nonEmpty = 0
    private var queued = 0
    private var queuedBytes = 0L
    private var nextSeq = 0L

    private fun groupOf(id: Long): Group {
        groups[id]?.let { return it }
        if (groups.size >= sweepAt) sweep()
        return Group(id).also { groups[id] = it }
    }

    /** Loop only: the group count that runs the next [sweep] (doubles with the groups kept, so a sweep is amortized O(1)). */
    private var sweepAt = SWEEP_AT

    private fun isRegistered(group: Long): Boolean =
        table
            .load()
            .find(group)
            ?.registered
            ?.load() == 1

    /**
     * Drops idle groups that were made at their first datagram and whose end is never reported (QUIC-level senders), with
     * their admissions when empty: a safety net that keeps both bounded. A group whose start was reported is never swept
     * (only its end removes it); a swept group that sends again gets its state anew.
     */
    private fun sweep() {
        groups.removeIf { it.queuedCount == 0 && !isRegistered(it.id) }
        sweepAt = maxOf(SWEEP_AT, groups.size * 2)
        for (a in table.load().admissions) {
            if (a.registered.load() == 0 && a.held.load() == 0 && groups[a.group] == null) {
                unregister(a.group)?.let {
                    it.channel.close()
                    closing += it
                }
            }
        }
    }

    private fun flowOf(
        g: Group,
        index: Int,
    ): Flow = g.flows[index] ?: Flow(g, index).also { g.flows[index] = it }

    private fun addLast(c: Cmd) {
        val g = groupOf(c.group)
        val f = flowOf(g, c.urgency + 1)
        c.seq = nextSeq++
        f.fifo.addLast(c)
        if (!f.inRing) {
            f.inRing = true
            f.deficit = 0
            rings[f.index].addLast(f)
            nonEmpty = nonEmpty or (1 shl f.index)
        }
        if (g.queuedCount == 0) {
            g.activeIndex = active.size
            active += g
        }
        g.queuedCount++
        g.queuedBytes += c.data.size
        queued++
        queuedBytes += c.data.size
    }

    /** Takes [f]'s oldest datagram; an emptied flow leaves its ring (it stays with its group). */
    private fun removeFirst(f: Flow): Cmd {
        val c = f.fifo.removeFirst()
        if (f.fifo.isEmpty()) leaveRing(f)
        taken(f.group, c)
        return c
    }

    private fun taken(
        g: Group,
        c: Cmd,
    ) {
        g.queuedCount--
        g.queuedBytes -= c.data.size
        queued--
        queuedBytes -= c.data.size
        if (g.queuedCount == 0) {
            val last = active.removeAt(active.size - 1)
            if (last !== g) {
                active[g.activeIndex] = last
                last.activeIndex = g.activeIndex
            }
            g.activeIndex = -1
            if (g.ended) groups.remove(g.id)
        }
    }

    private fun leaveRing(f: Flow) {
        f.inRing = false
        f.deficit = 0
        val ring = rings[f.index]
        if (ring.firstOrNull() === f) ring.removeFirst() else ring.remove(f)
        if (ring.isEmpty()) nonEmpty = nonEmpty and (1 shl f.index).inv()
    }

    /** The ring of the most urgent queued datagram, -1 when none. */
    private fun first(): Int = if (nonEmpty == 0) -1 else nonEmpty.countTrailingZeroBits()

    /** Any thread: true when a datagram under [DatagramPolicy.Reject] has room. */
    fun hasRoom(size: Int): Boolean = count.load() < maxCount && bytes.load() + size <= maxBytes

    /** Any thread: [group] starts (its request stream opened): its admission channel is made. */
    fun startGroup(group: Long) {
        if (group != NO_GROUP) admissionOf(group).registered.store(1)
    }

    /** Any thread: [group]'s admission, made and registered when it has none. */
    private fun admissionOf(group: Long): Admission {
        while (true) {
            val t = table.load()
            t.find(group)?.let { return it }
            val made = newAdmission(group)
            val i = -(t.indexOf(group) + 1)
            val keys = LongArray(t.groups.size + 1)
            t.groups.copyInto(keys, 0, 0, i)
            keys[i] = group
            t.groups.copyInto(keys, i + 1, i)
            val adms = arrayOfNulls<Admission>(t.admissions.size + 1)
            t.admissions.copyInto(adms, 0, 0, i)
            adms[i] = made
            t.admissions.copyInto(adms, i + 1, i)
            @Suppress("UNCHECKED_CAST")
            if (table.compareAndSet(t, Table(keys, adms as Array<Admission>))) return made
        }
    }

    /** Takes [group]'s admission out of the table (any thread); null when it had none. */
    private fun unregister(group: Long): Admission? {
        while (true) {
            val t = table.load()
            val i = t.indexOf(group)
            if (i < 0) return null
            val keys = LongArray(t.groups.size - 1)
            t.groups.copyInto(keys, 0, 0, i)
            t.groups.copyInto(keys, i, i + 1)
            val adms = arrayOfNulls<Admission>(t.admissions.size - 1)
            t.admissions.copyInto(adms, 0, 0, i)
            t.admissions.copyInto(adms, i, i + 1)
            @Suppress("UNCHECKED_CAST")
            if (table.compareAndSet(t, Table(keys, adms as Array<Admission>))) return t.admissions[i]
        }
    }

    /**
     * Any thread: hands [data] (already copied) over to [group]'s admission channel; [DatagramPolicy.Reject] callers check
     * [hasRoom] first. A caller that outruns the loop drops its own group's oldest unread command, never another group's.
     */
    fun offer(
        data: ByteArray,
        policy: DatagramPolicy,
        urgency: Int = -1,
        group: Long = NO_GROUP,
    ) {
        count.incrementAndFetch()
        bytes.addAndFetch(data.size.toLong())
        val cmd = Cmd(data, policy, urgency, group)
        while (true) {
            if (closed.load() != 0) {
                release(cmd) // the connection is gone
                return
            }
            val a = if (group == NO_GROUP) shared else admissionOf(group)
            a.held.incrementAndFetch()
            if (a.channel.trySend(cmd).isSuccess) {
                // a send that raced close() may have made an admission close() did not see: its commands are released
                if (closed.load() != 0) a.channel.cancel()
                break
            }
            a.held.decrementAndFetch()
            // the group ended between the lookup and the send (its channel is out of the table before it closes): the
            // next lookup makes it a new one; the shared one closes only with the queue
            if (a === shared) {
                release(cmd)
                return
            }
        }
        signal.trySend(Unit)
    }

    /**
     * Loop only: the next admitted command. Ended groups' admissions go first, each until it is empty (at most [maxCount]
     * commands each, and they precede anything the group's new admission holds, so order within a group is kept); then the
     * shared one and the registered groups' take turns, one command each, so no channel waits behind another's flood. Null
     * when none holds one.
     */
    private fun nextCommand(): Cmd? {
        while (closing.isNotEmpty()) {
            val a = closing[0]
            val r = a.channel.tryReceive()
            r.getOrNull()?.let {
                a.held.decrementAndFetch()
                return it
            }
            closing.removeAt(0) // closed before it was put here: empty means drained for good
            // an ended group whose admitted datagrams were all dropped on the way leaves no state
            groups[a.group]?.let { if (it.ended && it.queuedCount == 0) groups.remove(a.group) }
        }
        val adms = table.load().admissions
        val n = adms.size + 1
        for (k in 0 until n) {
            val i = (nextSource + k) % n
            val a = if (i < adms.size) adms[i] else shared
            a.channel.tryReceive().getOrNull()?.let {
                a.held.decrementAndFetch()
                nextSource = i + 1
                return it
            }
        }
        return null
    }

    /** A command taken from admission that did not fit yet. */
    private var pending: Cmd? = null

    /** Loop only: a command taken from admission waits for room. */
    val waiting: Boolean get() = pending != null

    /** Loop only: a command is waiting for room or in admission. */
    val hasPendingCommands: Boolean get() = pending != null || hasAdmitted()

    private fun hasAdmitted(): Boolean =
        shared.held.load() > 0 || table.load().admissions.any { it.held.load() > 0 } || closing.any { it.held.load() > 0 }

    /**
     * Loop only: one pass of the drainer, bounded by what is admitted when it starts. Admitted commands go into the queue and
     * [flush] lets the core send what the window allows; when a command still finds no room the eviction rules decide, for
     * the commands admitted before that pass only. True when more is admitted (senders that keep flooding): the caller
     * signals itself and yields, so the loop's other work (ACKs, timers, other connections) runs between passes. It never
     * waits for a producer (a producer's send is followed by its [signal]).
     */
    inline fun drain(flush: () -> Unit): Boolean {
        val added = applyCommands(budget = admittedNow())
        if (added || !isEmpty) flush()
        // the network did not take them: the policy decides who goes, for what was admitted before this pass only
        if (waiting && applyCommands(evict = true, budget = admittedNow())) flush()
        return waiting || hasAdmitted()
    }

    /** Commands in admission now (any thread's view): a drain pass takes no more than these. */
    internal fun admittedNow(): Int {
        var n = shared.held.load()
        for (a in table.load().admissions) n += a.held.load()
        for (a in closing) n += a.held.load()
        return n
    }

    /**
     * Loop only: moves admitted commands into the queue while it has room (a LatestWins replacement always fits); true when
     * something was added. With [evict], a command that finds the queue full makes room by the eviction rules instead of
     * waiting, and the whole admission is drained in one pass, so a flood cannot outrun the drainer.
     */
    fun applyCommands(
        evict: Boolean = false,
        budget: Int = Int.MAX_VALUE,
    ): Boolean {
        var any = false
        var taken = 0
        while (true) {
            // the command that did not fit last time goes first (order is kept); new ones only within the budget
            val cmd =
                pending ?: (if (taken < budget) nextCommand() else null)?.also { taken++ } ?: break
            pending = null
            if (cmd.policy is DatagramPolicy.LatestWins && replace(cmd)) {
                addLast(cmd)
                any = true
                continue
            }
            if (queued >= maxCount || queuedBytes + cmd.data.size > maxBytes) {
                if (!evict) {
                    pending = cmd
                    break
                } // full: the loop sends first, evicts only if that did not help
                if (!makeRoom(cmd)) continue // dropped itself: it was less urgent than its group's queued datagrams
            }
            addLast(cmd)
            any = true
        }
        return any
    }

    /** A queued datagram of [cmd]'s group under the same LatestWins key goes; true when one did. */
    private fun replace(cmd: Cmd): Boolean {
        val key = (cmd.policy as DatagramPolicy.LatestWins).key
        val g = groups[cmd.group] ?: return false
        for (f in g.flows) {
            if (f == null) continue
            val i = f.fifo.indexOfFirst { (it.policy as? DatagramPolicy.LatestWins)?.key == key }
            if (i < 0) continue
            val old = f.fifo.removeAt(i)
            if (f.fifo.isEmpty()) leaveRing(f)
            taken(g, old)
            release(old)
            return true
        }
        return false
    }

    /**
     * Loop only: the network could not take the queue; room is made for the pending command (DropOldest / LatestWins
     * semantics) by the eviction rules ([makeRoom]).
     */
    fun evictForPending() {
        val cmd = pending ?: return
        pending = null
        if (makeRoom(cmd)) addLast(cmd)
    }

    /**
     * Evicts until [cmd] fits: from the group with the most bytes queued (the sender's own on a tie); in the sender's own
     * group only from a flow of the same or a lower urgency, and when it has none [cmd] itself is dropped (false); in another
     * group from its least urgent flow. True when [cmd] may be queued.
     */
    private fun makeRoom(cmd: Cmd): Boolean {
        val index = cmd.urgency + 1
        while (queued > 0 && (queued >= maxCount || queuedBytes + cmd.data.size > maxBytes)) {
            var victim: Group? = null
            for (g in active) {
                if (victim == null ||
                    g.queuedBytes > victim.queuedBytes ||
                    (g.queuedBytes == victim.queuedBytes && g.id == cmd.group)
                ) {
                    victim = g
                }
            }
            val g = victim!!
            var f: Flow? = null
            for (i in URGENCIES - 1 downTo 0) {
                val c = g.flows[i]
                if (c != null && c.fifo.isNotEmpty()) {
                    f = c
                    break
                }
            }
            if (g.id == cmd.group && f!!.index < index) {
                release(cmd) // every datagram its group has queued is more urgent: the new one goes
                return false
            }
            release(removeFirst(f!!))
        }
        return true
    }

    /** Loop only: [group]'s stream ended; its state goes once its last datagram left (at once when none is queued). */
    fun endGroup(group: Long) {
        val a = unregister(group)
        if (a != null) {
            a.channel.close() // late sends fail and go to a new admission; what it holds is still drained
            closing += a
        }
        val g = groups[group]
        if (g == null) {
            // datagrams still in its admission: they come as an ended group, which goes once they left
            if (a != null && a.held.load() > 0) groups[group] = Group(group).also { it.ended = true }
            return
        }
        g.ended = true
        if (g.queuedCount == 0) groups.remove(group)
    }

    /** Datagrams queued for [group] (a test hook, loop only). */
    internal fun queuedForTest(group: Long): Int = groups[group]?.queuedCount ?: 0

    /** [group]'s admission (a test hook); null when it has none. */
    internal fun admissionForTest(group: Long): Admission? = if (group == NO_GROUP) shared else table.load().find(group)

    /** Admissions registered (a test hook). */
    internal val admissionCountForTest: Int get() = table.load().admissions.size

    /** Groups with state kept (a test hook, loop only). */
    internal val groupCountForTest: Int get() = groups.size

    val isFull: Boolean get() = queued >= maxCount || queuedBytes >= maxBytes

    /** Datagrams dropped because they outgrew the path MTU. */
    var dropped: Long = 0
        private set

    private fun release(c: Cmd) {
        count.decrementAndFetch()
        bytes.addAndFetch(-c.data.size.toLong())
    }

    val isEmpty: Boolean get() = queued == 0

    override fun hasPending(): Boolean = queued > 0

    /** The urgency of the most urgent queued datagram. */
    override fun nextUrgency(): Int = first().let { if (it < 0) -1 else it - 1 }

    /**
     * Writes datagrams of the most urgent ring only: the packet builder let more urgent stream data go first for that
     * urgency ([nextUrgency]), so a less urgent datagram waits for a packet of its own turn. The ring's flows take turns by
     * deficit round robin: a flow's turn adds [QUANTUM] bytes to its deficit and sends while its next datagram fits it.
     */
    override fun onTransmit(packet: DatagramPacketWriter) {
        val i = first()
        if (i < 0) return
        val ring = rings[i]
        while (true) {
            val f = ring.firstOrNull() ?: break
            val c = f.fifo.first()
            if (c.data.size > packet.maxPayload) {
                release(removeFirst(f))
                dropped++
                continue
            } // the path MTU shrank under it: it can never be sent (RFC 8899 black hole)
            if (c.data.size > packet.remaining) break
            if (f.deficit < c.data.size) {
                // the flow's turn is over: the next one's comes with its quantum
                f.deficit += QUANTUM
                if (ring.size > 1) {
                    ring.removeFirst()
                    ring.addLast(f)
                }
                continue
            }
            if (!packet.write(c.data, 0, c.data.size)) break
            f.deficit -= c.data.size
            release(removeFirst(f))
        }
    }

    fun close() {
        signal.close()
        closed.store(1) // first: later sends are dropped
        shared.channel.cancel()
        val t = table.exchange(Table(LongArray(0), emptyArray()))
        t.admissions.forEach { it.channel.cancel() } // their commands are released
        closing.forEach { it.channel.cancel() }
        closing.clear()
        rings.forEach { it.clear() }
        groups.clear()
        active.clear()
        nonEmpty = 0
        queued = 0
        queuedBytes = 0
        pending = null
    }

    internal companion object {
        /** -1 (no urgency) and RFC 9218's eight urgencies. */
        private const val URGENCIES = 9

        /** The group of datagrams that belong to none. */
        const val NO_GROUP: Long = Long.MIN_VALUE

        /** The bytes a flow's turn adds to its deficit: about one datagram of a full-size packet. */
        const val QUANTUM = 1200

        /** Groups kept before idle ones whose end was never reported are swept. */
        private const val SWEEP_AT = 1024
    }
}

/** A hash map of primitive `Long` keys (open addressing, linear probing, backward-shift deletion): no boxing per lookup. */
internal class LongMap<V : Any> {
    private var keys = LongArray(16)
    private var values = arrayOfNulls<Any>(16)
    var size = 0
        private set

    private fun slot(key: Long): Int {
        val h = (key xor (key ushr 32)).toInt() * -0x61c88647
        return h ushr (32 - keys.size.countTrailingZeroBits()) and (keys.size - 1)
    }

    @Suppress("UNCHECKED_CAST")
    operator fun get(key: Long): V? {
        var i = slot(key)
        while (true) {
            val v = values[i] ?: return null
            if (keys[i] == key) return v as V
            i = (i + 1) and (keys.size - 1)
        }
    }

    operator fun set(
        key: Long,
        value: V,
    ) {
        if ((size + 1) * 4 > keys.size * 3) grow()
        var i = slot(key)
        while (values[i] != null) {
            if (keys[i] == key) {
                values[i] = value
                return
            }
            i = (i + 1) and (keys.size - 1)
        }
        keys[i] = key
        values[i] = value
        size++
    }

    fun remove(key: Long) {
        val mask = keys.size - 1
        var i = slot(key)
        while (true) {
            if (values[i] == null) return
            if (keys[i] == key) break
            i = (i + 1) and mask
        }
        // backward-shift: later entries of the probe chain move into the gap
        var gap = i
        var j = (i + 1) and mask
        while (values[j] != null) {
            val home = slot(keys[j])
            val between = if (gap <= j) home in (gap + 1)..j else home in (gap + 1)..mask || home <= j
            if (!between) {
                keys[gap] = keys[j]
                values[gap] = values[j]
                gap = j
            }
            j = (j + 1) and mask
        }
        values[gap] = null
        size--
    }

    @Suppress("UNCHECKED_CAST")
    fun removeIf(predicate: (V) -> Boolean) {
        val doomed = ArrayList<Long>()
        for (i in keys.indices) {
            val v = values[i] ?: continue
            if (predicate(v as V)) doomed += keys[i]
        }
        for (k in doomed) remove(k)
    }

    fun clear() {
        values.fill(null)
        size = 0
    }

    private fun grow() {
        val oldKeys = keys
        val oldValues = values
        keys = LongArray(oldKeys.size * 2)
        values = arrayOfNulls(oldKeys.size * 2)
        size = 0
        @Suppress("UNCHECKED_CAST")
        for (i in oldKeys.indices) oldValues[i]?.let { set(oldKeys[i], it as V) }
    }
}
