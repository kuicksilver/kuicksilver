// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.toJavaAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.LeakRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runInterruptible
import java.net.StandardSocketOptions
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector

/**
 * Portable JVM/Android transport (ADR-0006): a non-blocking [DatagramChannel]; `receive` waits on a selector on
 * `Dispatchers.IO` and then drains as many datagrams as the batch holds, so bursts on fast links are not dropped
 * at the socket buffer one datagram at a time. [open] puts DF on through `ksl` on the JVM ([dfProbe]), so it loads the
 * native library (once per process) where it is not loaded yet; without it the socket still opens.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class NioDatagramIo private constructor(
    private val channel: DatagramChannel,
    private val selector: Selector,
) : DatagramIo,
    QueuedReceive,
    DfFamilyRestricted {
    override val localAddress: InetSocketAddress =
        (channel.localAddress as java.net.InetSocketAddress).let {
            InetSocketAddress(checkNotNull(it.address.hostAddress) { "the local address has no host address" }, it.port)
        }
    private val caps = MutableStateFlow(IoCapabilities.Portable)
    override val capabilities: StateFlow<IoCapabilities> get() = caps

    /** ADR-0006: the portable socket marks every datagram ECT(0) through IP_TOS (no per-datagram control, no reading of marks). */
    private fun enableEcn() {
        try {
            channel.setOption(StandardSocketOptions.IP_TOS, 0x02)
            caps.value =
                IoCapabilities(ecnSend = true, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = false, batch = 1)
        } catch (
            e: Exception,
        ) {
            caps.value =
                IoCapabilities.Portable
        }
    }

    override fun disableEcnMarking() {
        try {
            channel.setOption(StandardSocketOptions.IP_TOS, 0)
        } catch (e: Exception) {
        }
        caps.value =
            IoCapabilities.Portable
    }

    internal fun ipTosForTest(): Int = channel.getOption(StandardSocketOptions.IP_TOS)

    /** The socket's IP_DONTFRAGMENT, or null where the JDK has no such option (test hook). */
    internal fun dontFragmentForTest(): Boolean? =
        dontFragmentOption()
            ?.takeIf {
                it in channel.supportedOptions()
            }?.let { channel.getOption(it) }

    /** What [open] got from [dfProbe]: the `DF_*` bits, 0 none (Apple), -1 no means (the JVM without `ksl`) (test hook). */
    internal var dfProbeGranted: Int = -1
        private set

    /** The address family whose sends go without DF and are refused (4 or 6), [DF_ALL] none ([noDfFamily]). */
    internal var noDf: Int = DF_ALL
        private set

    override val noDontFragmentFamily: IpFamily? get() = noDfFamily

    override val noDfFamily: IpFamily?
        get() =
            when (noDf) {
                4 -> IpFamily.V4
                6 -> IpFamily.V6
                else -> null
            }

    /** Destinations a send refused for want of DF ([sendFrom]), taken by the endpoint loop after each batch. */
    private val dfRefused = ArrayList<InetSocketAddress>(2)

    override fun takeDfRefusals(): List<InetSocketAddress> {
        if (dfRefused.isEmpty()) return emptyList()
        val out = dfRefused.toList()
        dfRefused.clear()
        return out
    }

    /** `IP_MTU_DISCOVER` ([family] 4) or `IPV6_MTU_DISCOVER` (6) of the socket while it is open, -1 when unreadable (test hook). */
    internal fun dfModeForTest(family: Int): Int = dfModeOf(channel, family)

    private var lastJava: java.net.InetSocketAddress? = null
    private var lastKtor: InetSocketAddress? = null
    private var sendJava: java.net.InetSocketAddress? = null
    private var sendKtor: InetSocketAddress? = null

    private fun ktorOf(a: java.net.InetSocketAddress): InetSocketAddress {
        if (a ==
            lastJava
        ) {
            return lastKtor!!
        }
        val k = InetSocketAddress(checkNotNull(a.address.hostAddress) { "the peer address has no host address" }, a.port)
        lastJava = a
        lastKtor = k
        return k
    }

    private fun javaOf(a: InetSocketAddress): java.net.InetSocketAddress {
        if (a ===
            sendKtor
        ) {
            return sendJava!!
        }
        val j = a.toJavaAddress() as java.net.InetSocketAddress
        sendKtor = a
        sendJava = j
        return j
    } // the underlying object: no reverse lookup

    private fun drain(into: PacketBatch): Int {
        var n = 0
        while (into.count < into.capacity) {
            val i = into.count
            val view = into.buffer(i).asByteBuffer()
            val from = channel.receive(view) as? java.net.InetSocketAddress ?: break
            into.setLength(i, view.position())
            into.setAddress(i, ktorOf(from))
            into.setEcn(i, Ecn.NotEct)
            n++
        }
        return n
    }

    /** Set by [interruptReceive]: the receive in flight returns 0. */
    private val interrupted =
        java.util.concurrent.atomic
            .AtomicBoolean(false)

    /** What the channel holds now, on the calling thread; 0 once it is closed. */
    override fun receiveQueued(into: PacketBatch): Int =
        try {
            if (channel.isOpen) drain(into) else 0
        } catch (_: java.nio.channels.ClosedChannelException) {
            0
        }

    /** Wakes the selector the receive in flight waits on; it returns 0 unless datagrams came. */
    override fun interruptReceive() {
        interrupted.set(true)
        try {
            selector.wakeup()
        } catch (_: java.nio.channels.ClosedSelectorException) {
        }
    }

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        interrupted.set(false) // left by a receive that returned with datagrams before it looked
        val immediate = drain(into)
        if (immediate > 0) return immediate
        return runInterruptible(Dispatchers.IO) {
            while (true) {
                if (!channel.isOpen) throw java.io.IOException("datagram channel closed")
                if (interrupted.getAndSet(false)) return@runInterruptible 0
                selector.select()
                // a cancelled receive: runInterruptible interrupted this thread, which makes select return at once without
                // throwing; with the flag still set every later select returns at once too, so the loop spun forever and the
                // cancellation never ended the call. The interrupt ends it here (runInterruptible makes it the cancellation)
                // Thread.interrupted() also clears the flag before drain reads the channel: an interruptible channel operation
                // started on an interrupted thread closes the channel (AbstractInterruptibleChannel.begin, and old Android
                // libcore's the same way, with ClosedByInterruptException), which would end the socket, not the receive. An
                // interrupt that lands during drain itself still closes it there; runInterruptible's interrupt comes only
                // with the cancellation, which ends the receive either way
                if (Thread.interrupted()) throw InterruptedException("receive cancelled")
                selector.selectedKeys().clear()
                val n = drain(into)
                if (n > 0) return@runInterruptible n
                if (interrupted.getAndSet(false)) return@runInterruptible 0
            }
            @Suppress("UNREACHABLE_CODE")
            0
        }
    }

    /** Registered for OP_WRITE only; `send` waits on it when the socket buffer is full (the read selector belongs to `receive`). */
    private val writeSelector: Selector =
        Selector.open().also {
            try {
                writeSelectorOpenedForTest?.invoke(it)
                channel.register(it, SelectionKey.OP_WRITE)
            } catch (e: Throwable) {
                closeAfter(it, e)
                throw e
            }
        }

    /** The leak sentinel's record of this socket (0 in production); the last to be set up, so a failed construction has none. */
    private val leakId = LeakRegistry.open("udp.socket")

    override suspend fun send(batch: PacketBatch): Int {
        var sent = sendFrom(batch, 0)
        if (sent < batch.count && channel.isOpen) {
            // the send buffer is full: wait once, briefly, for room and send the rest; what still does not fit is lost (counted by the loop)
            runInterruptible(Dispatchers.IO) {
                writeSelector.select(WRITE_WAIT_MS)
                writeSelector.selectedKeys().clear()
            }
            sent = sendFrom(batch, sent)
        }
        return sent
    }

    override fun trySend(batch: PacketBatch): Int = sendFrom(batch, 0)

    /**
     * Sends the slots of [batch] from [from] in order until the socket refuses one (a full buffer); returns the index of the first
     * slot not sent. A slot to an address family without DF is skipped and reported ([takeDfRefusals]).
     */
    private fun sendFrom(
        batch: PacketBatch,
        from: Int,
    ): Int {
        for (i in from until batch.count) {
            val a =
                batch.address(i) ?: continue // nothing to send: not a refusal
            val view = batch.buffer(i).asByteBuffer()
            view.limit(batch.length(i))
            val to = javaOf(a)
            // no DF towards that family: this slot is not sent (no QUIC without DF) and the endpoint loop learns where it went;
            // the rest of the batch goes on
            if (noDf != DF_ALL && refusesWithoutDf(noDf, to)) {
                dfRefused += a
                continue
            }
            val n =
                sendRefusalAware(batch.length(i), a, emsgsizeText) {
                    view.position(0)
                    channel.send(view, to)
                }
            if (n == 0 && batch.length(i) > 0) return i // a non-blocking channel takes all or nothing
        }
        return batch.count
    }

    override fun close() {
        channel.close()
        selector.wakeup()
        selector.close()
        writeSelector.wakeup()
        writeSelector.close()
        LeakRegistry.close(leakId)
    }

    companion object {
        /**
         * `jdk.net.ExtendedSocketOptions.IP_DONTFRAGMENT` (JDK 19 and later; looked up by reflection, since the build targets
         * Java 17 and Android has none), or null where the runtime lacks it.
         */
        private val dontFragment: java.net.SocketOption<Boolean>? by lazy {
            try {
                @Suppress("UNCHECKED_CAST")
                Class.forName("jdk.net.ExtendedSocketOptions").getField("IP_DONTFRAGMENT").get(null) as java.net.SocketOption<Boolean>
            } catch (_: ReflectiveOperationException) {
                null
            } catch (_: ClassCastException) {
                null
            } catch (_: LinkageError) {
                null
            }
        }

        private fun dontFragmentOption(): java.net.SocketOption<Boolean>? = dontFragment

        /** Whether this runtime has the JDK's `IP_DONTFRAGMENT` (the gate [triesInet] is given) (test hook). */
        internal fun hasJdkDontFragmentForTest(): Boolean = dontFragmentOption() != null

        /**
         * Whether [to] is of the address family [noDf] whose traffic this socket cannot give DF (the other half of a dual-stack
         * socket has it), or IPv6 on an AF_INET socket ([noDf] 6). An IPv4-mapped literal counts as IPv4: java.net makes it an
         * `Inet4Address`.
         */
        internal fun refusesWithoutDf(
            noDf: Int,
            to: java.net.InetSocketAddress,
        ): Boolean = (if (to.address is java.net.Inet4Address) 4 else 6) == noDf

        /** [localizedEmsgsizeText], read once ([systemEmsgsizeText]). */
        private val emsgsizeText: String? get() = systemEmsgsizeText()

        /**
         * EMSGSIZE / WSAEMSGSIZE as the JDK reports a send's: the system's `strerror(EMSGSIZE)` under the process's locale
         * ([localized], through `ksl`; the JDK formats errno under `setlocale(LC_ALL, "")`), its English text "Message too
         * long" (Linux and Apple in the C locale; Android adds "EMSGSIZE"), and on Windows the JDK's own text for WSAEMSGSIZE
         * (net_util_md.c: "The message is larger than the maximum supported by the underlying transport"). Without `ksl` under
         * a non-English locale a Linux refusal is not recognized: its datagrams are lost until the idle timeout. The texts are
         * [namesEmsgsize]'s, which [isRefusedAsTooLarge] (the CONNECT-UDP proxy's) reads too.
         */
        internal fun isMessageTooLong(
            e: java.net.SocketException,
            localized: String? = null,
        ): Boolean = e.message?.let { namesEmsgsize(it, localized) } == true

        /**
         * One datagram of [len] bytes to [to] through [send]. A refusal as too large of a datagram of at most 1200 bytes is a
         * failed path ([PathMtuRefusedException]) only when the immediate retry is refused too: a connected socket gets an ICMP
         * message as a one-shot socket error (Linux `sk_err`, even in probe mode), which the retry clears, while DO mode refuses
         * every send above the cached MTU. Other exceptions, and refusals of larger datagrams, propagate.
         */
        internal inline fun sendRefusalAware(
            len: Int,
            to: InetSocketAddress,
            localized: String?,
            send: () -> Int,
        ): Int {
            try {
                return send()
            } catch (e: java.net.SocketException) {
                if (len > PATH_MTU_FLOOR || !isMessageTooLong(e, localized)) throw e
            }
            try {
                return send()
            } catch (e: java.net.SocketException) {
                if (isMessageTooLong(e, localized)) throw PathMtuRefusedException(len, to, e)
                throw e
            }
        }

        /**
         * Whether the JDK's `IP_DONTFRAGMENT` is set, given the [dfProbe] bits: when nothing put DF on the half of the socket
         * the JDK's option covers (an AF_INET socket's only half; on an AF_INET6 socket the JDK sets `IPV6_MTU_DISCOVER`
         * only, the IPv6 half). That is DO mode on Linux and Windows, `IP_DONTFRAG` on Apple: DF always.
         */
        internal fun usesJdkDontFragment(bits: Int): Boolean {
            if (bits <= 0) return true
            return if (bits and DF_INET6 != 0) bits and (DF_V6 or DF_V6_DO) == 0 else bits and (DF_V4 or DF_V4_DO) == 0
        }

        private val linuxKernel = (System.getProperty("os.name") ?: "").lowercase().startsWith("linux")

        /** Set once the first socket without probe mode on every half was reported. */
        private val probeMissingLogged =
            java.util.concurrent.atomic
                .AtomicBoolean(false)

        private val apple = onDarwin

        /** [noDfFamily]: every half of the socket has DF. */
        internal const val DF_ALL = 0

        /** [noDfFamily]: no traffic of the socket can have DF: QUIC is not used on it. */
        internal const val DF_NONE = -1

        /**
         * Which traffic of the socket goes without DF: [DF_ALL] none, 4 or 6 the IPv4 or IPv6 half of a dual-stack socket,
         * [DF_NONE] all of it. [bits] from [dfProbe], [jdkSet] whether the JDK's `IP_DONTFRAGMENT` took, [inet] whether the
         * channel is AF_INET, [onApple] whether the JDK's option is Darwin's: on an AF_INET6 socket that is `IPV6_DONTFRAG`,
         * which covers v4-mapped traffic too (checked on macOS 26 with the host JVM: 20000 bytes to `::ffff:127.0.0.1` through
         * such a socket are refused with EMSGSIZE, above lo0's 16384, and go out fragmented without it, though `IP_DONTFRAG`
         * cannot be read at the IPv4 level of that socket, EINVAL). On Linux and Windows the JDK's option on an AF_INET6
         * socket sets the IPv6 half only.
         */
        internal fun noDfFamily(
            bits: Int,
            jdkSet: Boolean,
            inet: Boolean,
            onApple: Boolean,
        ): Int {
            val v4ByKsl = bits > 0 && bits and (DF_V4 or DF_V4_DO) != 0
            if (inet) return if (v4ByKsl || jdkSet) DF_ALL else DF_NONE
            val v4 = v4ByKsl || (onApple && jdkSet)
            val v6 = (bits > 0 && bits and (DF_V6 or DF_V6_DO) != 0) || jdkSet
            return when {
                v4 && v6 -> DF_ALL
                v6 -> 4
                v4 -> 6
                else -> DF_NONE
            }
        }

        /**
         * Whether a socket without DF stays so for the process ([QuicException.DontFragmentUnavailable.permanent]): not when the
         * probe itself failed ([DF_PROBE_FAILED], Android out of descriptors), which a later socket may pass.
         */
        internal fun dfLackPermanent(bits: Int): Boolean = bits != DF_PROBE_FAILED

        /** Why DF could not be set, for [QuicException.DontFragmentUnavailable]. */
        internal fun dfUnavailableDetail(
            bits: Int,
            jdkOption: Boolean,
        ): String =
            when {
                bits == DF_PROBE_FAILED -> "the DF probe itself failed (for example out of file descriptors); a later socket may get DF"
                bits == DF_NO_DESCRIPTOR -> "this Android runtime does not give the socket's descriptor, so DF cannot be set on it"
                bits > 0 -> "the system refused both DF modes (probe and DO) on that half (bits $bits)"
                bits == 0 -> "the system offers no DF option to set"
                jdkOption -> "the JDK's IP_DONTFRAGMENT did not take and the ksl native library is not available"
                else -> "the ksl native library is not available and this JDK (below 19) has no IP_DONTFRAGMENT"
            }

        private fun jdkDontFragment(ch: DatagramChannel): Boolean {
            val opt = dontFragmentOption() ?: return false
            return try {
                if (opt in ch.supportedOptions()) {
                    ch.setOption(opt, true)
                    true
                } else {
                    false
                }
            } catch (_: java.io.IOException) {
                false
            } catch (_: UnsupportedOperationException) {
                false
            }
        }

        /** Tests: the DF outcome of a new channel (AF_INET or not) as ([dfProbe] bits, whether the JDK's option took), instead of setting it. */
        @kotlin.concurrent.Volatile
        internal var dfForTest: ((inet: Boolean) -> Pair<Int, Boolean>)? = null

        /** Tests: every channel [open] opens, as soon as it is open (before its buffers and DF are set). */
        @kotlin.concurrent.Volatile
        internal var channelOpenedForTest: ((DatagramChannel) -> Unit)? = null

        /** Tests: runs on the channel [open] drops (of the AF_INET and dual-stack ones) just before closing it; may throw. */
        @kotlin.concurrent.Volatile
        internal var closingDroppedForTest: ((DatagramChannel) -> Unit)? = null

        /** Tests: runs in [open] after the channel is registered with its selector, before the socket is made; may throw. */
        @kotlin.concurrent.Volatile
        internal var registeredForTest: ((DatagramChannel, Selector) -> Unit)? = null

        /** Tests: runs in the socket's construction on its new write selector, before the channel is registered; may throw. */
        @kotlin.concurrent.Volatile
        internal var writeSelectorOpenedForTest: ((Selector) -> Unit)? = null

        /** Closes [c] after [cause] ended its use; a failure of the close is added to [cause], never hides it. */
        private fun closeAfter(
            c: java.io.Closeable,
            cause: Throwable,
        ) {
            try {
                c.close()
            } catch (f: Throwable) {
                cause.addSuppressed(f)
            }
        }

        /** A channel with its DF state: the [dfProbe] bits, whether the JDK's option took, whether it is AF_INET. */
        private class ChannelDf(
            val ch: DatagramChannel,
            val bits: Int,
            val jdk: Boolean,
            val inet: Boolean,
        )

        /**
         * A channel with the buffers and DF of [open]: AF_INET when [inet], else AF_INET6 (dual-stack) where the runtime has
         * IPv6, AF_INET otherwise, so the family is always known.
         */
        private fun newChannel(inet: Boolean): ChannelDf {
            var isInet = inet
            val ch =
                if (inet) {
                    DatagramChannel.open(java.net.StandardProtocolFamily.INET)
                } else {
                    try {
                        DatagramChannel.open(java.net.StandardProtocolFamily.INET6)
                    } catch (_: UnsupportedOperationException) {
                        isInet = true
                        DatagramChannel.open(java.net.StandardProtocolFamily.INET)
                    }
                }
            try {
                channelOpenedForTest?.invoke(ch)
                ch.setOption(StandardSocketOptions.SO_RCVBUF, 8 shl 20)
                ch.setOption(StandardSocketOptions.SO_SNDBUF, 8 shl 20)
                dfForTest?.let { f ->
                    val (bits, jdk) = f(isInet)
                    return ChannelDf(ch, bits, jdk, isInet)
                }
                val bits = dfProbe(ch)
                val jdk = usesJdkDontFragment(bits) && jdkDontFragment(ch)
                return ChannelDf(ch, bits, jdk, isInet)
            } catch (e: Throwable) {
                closeAfter(ch, e)
                throw e
            }
        }

        /**
         * The channel for [local], with DF on all its traffic, or none at all: QUIC is not used without DF (owner decision for
         * RFC 9000 section 14: "UDP datagrams MUST NOT be fragmented at the IP layer. In IPv4, the Don't Fragment (DF) bit MUST
         * be set if possible"; section 14.2.1: an endpoint "MUST ignore an ICMP message that claims the PMTU has decreased below
         * QUIC's smallest allowed maximum datagram size").
         * - Probe mode (`IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE`, per half: [dfProbe], through `ksl` on the JVM and
         *   `android.system.Os` on Android) meets both: no fragmentation, and no path MTU cache an ICMP message could lower.
         * - A half that refuses probe mode (`ksl` present but the system says no: a seccomp filter, gVisor, Windows without the
         *   option) gets DO mode; Apple has only DO-like `IP_DONTFRAG` / `IPV6_DONTFRAG` (set through `ksl`); without `ksl`
         *   the JDK's `IP_DONTFRAGMENT` (JDK 19 and later) is set, DO mode on Linux and Windows. DO mode never fragments
         *   either, but there section 14.2.1 is a limitation the system imposes: a forged ICMP message claiming less than
         *   1200 makes it refuse sends to that peer (Linux EMSGSIZE for ten minutes; Windows WSAEMSGSIZE, verified on a
         *   Windows 11 VM against a non-loopback peer, loopback unaffected). Such a refusal of a datagram of at most 1200
         *   bytes, repeated on the retry, is [PathMtuRefusedException]: the endpoint loop closes that path, or the connection
         *   with NO_VIABLE_PATH (an HTTP/3 client falls back to TCP).
         * - The JDK's option on a dual-stack (AF_INET6) channel sets only the IPv6 half on Linux and Windows. So when the IPv4
         *   traffic of the dual-stack channel has no DF and [local] is IPv4, an AF_INET channel is tried ([triesInet]: through
         *   the JDK's option, or through [dfProbe] where its bits say it refused the IPv4 half, `ksl` on the JVM and
         *   `android.system.Os` on Android, Apple included) and kept if DF took on it (bound to 0.0.0.0 it then reaches IPv4
         *   peers only).
         * - Where a half of a dual-stack socket still has no DF, sends to that address family throw
         *   [QuicException.DontFragmentUnavailable] (the connection ends with no viable path); where no traffic can have DF
         *   (the JVM without `ksl` below JDK 19; Android or a system refusing both modes; on the AF_INET channel too, for an
         *   IPv4 bind) [open] throws it.
         * This socket's datagrams stay within 1200 bytes, so PMTUD stays off (`df` capability false); with probe mode it could
         * run here later. Returns the channel, the [dfProbe] bits and the address family without DF ([DF_ALL]: none).
         */
        private fun openWithDf(local: InetSocketAddress): Triple<DatagramChannel, Int, Int> {
            val localV6 = local.ipBytesNoDns()?.size == 16
            var c = newChannel(inet = false)
            if (!c.inet && triesInet(c.bits, c.jdk, localV6, apple, dontFragmentOption() != null)) {
                val r =
                    try {
                        newChannel(inet = true)
                    } catch (e: Throwable) {
                        closeAfter(c.ch, e) // out of descriptors, say: the dual-stack channel must not leak
                        throw e
                    }
                // the AF_INET channel when DF took on it, else the dual-stack one (it also reaches IPv6 peers)
                val (kept, dropped) = if (keepsInet(r.bits, r.jdk)) r to c else c to r
                try {
                    closingDroppedForTest?.invoke(dropped.ch)
                    dropped.ch.close()
                } catch (e: Throwable) {
                    closeAfter(kept.ch, e)
                    throw e
                }
                c = kept
            }
            val missing = noDfFamily(c.bits, c.jdk, c.inet, apple)
            if (missing == DF_NONE) {
                val e =
                    QuicException.DontFragmentUnavailable(
                        null,
                        dfUnavailableDetail(c.bits, dontFragmentOption() != null),
                        permanent = dfLackPermanent(c.bits),
                    )
                closeAfter(c.ch, e)
                throw e
            }
            if ((c.bits > 0 || (c.bits == 0 && linuxKernel)) && !probeComplete(c.bits) && probeMissingLogged.compareAndSet(false, true)) {
                printWarning(
                    "kuicksilver: the portable UDP socket has no DF probe mode on every half (bits ${c.bits}): DO mode, so a " +
                        "forged ICMP message can end its connections (RFC 9000 section 14.2.1)",
                )
            }
            // an AF_INET channel (an IPv4 bind that took DF only there) cannot reach IPv6 at all: refused as without DF
            return Triple(c.ch, c.bits, if (c.inet && missing == DF_ALL) 6 else missing)
        }

        /**
         * Whether to try an AF_INET channel for a bind address that is not IPv6 ([localV6] false): the dual-stack channel's
         * IPv4 traffic has no DF ([noDfFamily] of its [bits] from [dfProbe] and [jdkSet], whether the JDK's option took, is 4
         * or [DF_NONE]; on Apple ([onApple]) the JDK's option and `IPV6_DONTFRAG` cover v4-mapped traffic, so there only when
         * they did not take), and something can put DF on the AF_INET channel: [dfProbe] where it had means here ([bits]
         * positive: `ksl` on the JVM, `android.system.Os` on Android; its IPv4 half was refused, so it is tried on AF_INET,
         * on any JDK), else the JDK's option ([jdkOption], JDK 19 and later; on Linux and Windows it sets only the IPv6 half of
         * a dual-stack channel). Whether a system takes on AF_INET what it refused on the IPv4 half of an AF_INET6 socket is
         * not known for any system (a sandbox or a Windows build refusing IPPROTO_IP options on dual-stack sockets would; not
         * observed): trying costs one more channel, and RFC 9000 section 14 asks for DF "if possible".
         */
        internal fun triesInet(
            bits: Int,
            jdkSet: Boolean,
            localV6: Boolean,
            onApple: Boolean,
            jdkOption: Boolean,
        ): Boolean {
            if (localV6) return false
            val missing = noDfFamily(bits, jdkSet, inet = false, onApple = onApple)
            if (missing != 4 && missing != DF_NONE) return false
            return bits > 0 || jdkOption
        }

        /** Whether the AF_INET channel [triesInet] opened is kept: only when DF took on it ([inetBits] from [dfProbe], [inetJdk]). */
        internal fun keepsInet(
            inetBits: Int,
            inetJdk: Boolean,
        ): Boolean = dfComplete(inetBits) || inetJdk

        /** How long a send waits for room in a full socket buffer before the rest of its batch is lost. */
        private const val WRITE_WAIT_MS = 5L

        /**
         * [configure] runs on the unbound channel before `bind` (Android binds it to a network); if anything throws, the channel
         * is closed. It should not connect the channel: a connected socket also gets an ICMP message as a one-shot error on its
         * next send (Linux, even in probe mode), which [sendRefusalAware] then retries once.
         */
        fun open(
            local: InetSocketAddress,
            configure: (DatagramChannel) -> Unit = {},
        ): NioDatagramIo {
            val (ch, probe, noDf) = openWithDf(local)
            val selector: Selector
            try {
                configure(ch)
                ch.bind(local.toJavaAddress())
                ch.configureBlocking(false)
                selector = Selector.open()
            } catch (e: Throwable) {
                closeAfter(ch, e) // a failure of the close itself must not hide why the open failed
                throw e
            }
            val io =
                try {
                    ch.register(selector, SelectionKey.OP_READ)
                    registeredForTest?.invoke(ch, selector)
                    NioDatagramIo(ch, selector)
                } catch (e: Throwable) {
                    closeAfter(selector, e)
                    closeAfter(ch, e)
                    throw e
                }
            return io.also {
                it.dfProbeGranted = probe
                it.noDf = noDf
                it.enableEcn()
            }
        }
    }
}
