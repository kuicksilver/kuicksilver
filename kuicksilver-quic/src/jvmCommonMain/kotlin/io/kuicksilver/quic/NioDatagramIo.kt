// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.toJavaAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
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
    QueuedReceive {
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
    private val writeSelector: Selector = Selector.open().also { channel.register(it, SelectionKey.OP_WRITE) }

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

    /** Sends the slots of [batch] from [from] in order until the socket refuses one; returns the index of the first slot not sent. */
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

        /** [localizedEmsgsizeText], read once. */
        private val emsgsizeText: String? by lazy { localizedEmsgsizeText() }

        /**
         * EMSGSIZE / WSAEMSGSIZE as the JDK reports a send's: the system's `strerror(EMSGSIZE)` under the process's locale
         * ([localized], through `ksl`; the JDK formats errno under `setlocale(LC_ALL, "")`), its English text "Message too
         * long" (Linux and Apple in the C locale; Android adds "EMSGSIZE"), and on Windows the JDK's own text for WSAEMSGSIZE
         * (net_util_md.c: "The message is larger than the maximum supported by the underlying transport"). Without `ksl` under
         * a non-English locale a Linux refusal is not recognized: its datagrams are lost until the idle timeout.
         */
        internal fun isMessageTooLong(
            e: java.net.SocketException,
            localized: String? = null,
        ): Boolean {
            val m = e.message ?: return false
            return (!localized.isNullOrEmpty() && m.contains(localized)) || m.contains("Message too long", ignoreCase = true) ||
                m.contains("EMSGSIZE") || m.contains("larger than the maximum supported by the underlying transport", ignoreCase = true)
        }

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

        private val apple = (System.getProperty("os.name") ?: "").lowercase().let { it.contains("mac") || it.contains("darwin") }

        /** Set once the first socket with a half that has no DF was reported. */
        private val dfMissingLogged =
            java.util.concurrent.atomic
                .AtomicBoolean(false)

        /**
         * Why some traffic of the socket goes without DF, or null when none does: [bits] from [dfProbe], [jdkSet] whether the
         * JDK's `IP_DONTFRAGMENT` took, [inet] whether the channel was opened AF_INET, [onApple] whether the JDK's option is
         * Darwin's. On an AF_INET6 socket that option is `IPV6_DONTFRAG` on Darwin, which covers v4-mapped traffic too:
         * checked on macOS 26 with the host JVM, where 20000 bytes to `::ffff:127.0.0.1` through such a socket are refused
         * (EMSGSIZE, above lo0's 16384) and go out fragmented without it, though `IP_DONTFRAG` cannot be read at the IPv4
         * level of that socket (EINVAL). On Linux and Windows it covers the IPv6 half of an AF_INET6 socket only.
         */
        internal fun dfGap(
            bits: Int,
            jdkSet: Boolean,
            inet: Boolean,
            onApple: Boolean,
        ): String? {
            if (dfComplete(bits)) return null
            if (!jdkSet) return if (bits > 0) BOTH_REFUSED else NO_MEANS
            if (inet || onApple) return null
            // the JDK's option covered the IPv6 half of a dual-stack channel; the IPv4 half is only covered by ksl
            val v4 = bits > 0 && bits and (DF_V4 or DF_V4_DO) != 0
            return if (v4) null else MAPPED_WITHOUT_DF
        }

        private const val BOTH_REFUSED = "a half refused both probe and DO mode"
        private const val NO_MEANS = "no means to set DF: the JVM without ksl below JDK 19, or Android refusing the options"
        private const val MAPPED_WITHOUT_DF =
            "IPv4-mapped traffic of a dual-stack socket (an IPv6 bind address, or an AF_INET channel that took no DF either)"

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

        /** A channel with the buffers and DF of [open]: [inet] opens it AF_INET; returns it, the [dfProbe] bits and whether the JDK's option took. */
        private fun newChannel(inet: Boolean): Triple<DatagramChannel, Int, Boolean> {
            val ch = if (inet) DatagramChannel.open(java.net.StandardProtocolFamily.INET) else DatagramChannel.open()
            try {
                ch.setOption(StandardSocketOptions.SO_RCVBUF, 8 shl 20)
                ch.setOption(StandardSocketOptions.SO_SNDBUF, 8 shl 20)
                val bits = dfProbe(ch)
                val jdk = usesJdkDontFragment(bits) && jdkDontFragment(ch)
                return Triple(ch, bits, jdk)
            } catch (e: Throwable) {
                ch.close()
                throw e
            }
        }

        /**
         * The channel for [local], with DF where possible. RFC 9000 section 14: "UDP datagrams MUST NOT be fragmented at the IP
         * layer. In IPv4, the Don't Fragment (DF) bit MUST be set if possible"; section 14.2.1: an endpoint "MUST ignore an
         * ICMP message that claims the PMTU has decreased below QUIC's smallest allowed maximum datagram size".
         * - Probe mode (`IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE`, per half: [dfProbe], through `ksl` on the JVM and
         *   `android.system.Os` on Android) meets both: no fragmentation, and no path MTU cache an ICMP message could lower.
         * - A half that refuses probe mode (`ksl` present but the system says no: a seccomp filter, gVisor, Windows without the
         *   option) gets DO mode; where nothing could be asked (the JVM without `ksl`) the JDK's `IP_DONTFRAGMENT` (JDK 19 and
         *   later) is set: DO mode on Linux and Windows, `IP_DONTFRAG` on Apple (no modes). DO mode never fragments either, but
         *   there section 14.2.1 is a limitation the system imposes: a forged ICMP message claiming less than 1200 makes it
         *   refuse sends to that peer (Linux EMSGSIZE for ten minutes; Windows WSAEMSGSIZE, verified on a Windows 11 VM against
         *   a non-loopback peer, loopback unaffected). Such a refusal of a datagram of at most 1200 bytes, repeated on the
         *   retry, is [PathMtuRefusedException]: the endpoint loop closes that path, or the connection with NO_VIABLE_PATH (an
         *   HTTP/3 client falls back to TCP), instead of losing datagrams until the idle timeout.
         * - The JDK's option on a dual-stack (AF_INET6) channel sets only the IPv6 half on Linux and Windows. So when the IPv4
         *   half has no DF and [local] is IPv4, the channel is opened AF_INET instead (bound to 0.0.0.0 it then reaches IPv4
         *   peers only); bound to an IPv6 address, its IPv4-mapped traffic goes without DF (not possible there without `ksl`).
         * - Not possible at all: the JVM without `ksl` below JDK 19 (no `IP_DONTFRAGMENT`), Android where the options are
         *   refused. A warning is logged once for such a socket, and once for a socket without probe mode on every half.
         * Real QUIC with kuicksilver's TLS needs `ksl`, which sets probe mode; the other cases matter where the system refuses
         * it or with a third-party `QuicCrypto`. This socket's datagrams stay within 1200 bytes, so PMTUD stays off (`df`
         * capability false); with probe mode it could run here later. Returns the channel and the [dfProbe] bits.
         */

        /**
         * Whether to try an AF_INET channel for a bind address that is not IPv6 ([localV6] false): the dual-stack channel's
         * IPv4 half has no DF ([bits] from [dfProbe]: no `ksl`, or `ksl` whose IPv4 half refused both modes), and the JDK's
         * option, which on Linux and Windows sets only the IPv6 half of a dual-stack channel, exists ([jdkOption]). Not on
         * Apple ([onApple]), where it covers v4-mapped traffic.
         */
        internal fun triesInet(
            bits: Int,
            localV6: Boolean,
            onApple: Boolean,
            jdkOption: Boolean,
        ): Boolean {
            if (localV6 || onApple || !jdkOption || dfComplete(bits)) return false
            return bits <= 0 || (bits and DF_INET6 != 0 && bits and (DF_V4 or DF_V4_DO) == 0)
        }

        /** Whether the AF_INET channel [triesInet] opened is kept: only when DF took on it ([inetBits] from [dfProbe], [inetJdk]). */
        internal fun keepsInet(
            inetBits: Int,
            inetJdk: Boolean,
        ): Boolean = dfComplete(inetBits) || inetJdk

        private fun openWithDf(local: InetSocketAddress): Pair<DatagramChannel, Int> {
            val localV6 = local.ipBytesNoDns()?.size == 16
            var (ch, bits, jdk) = newChannel(inet = false)
            var inet = false
            if (triesInet(bits, localV6, apple, dontFragmentOption() != null)) {
                val r = newChannel(inet = true)
                if (keepsInet(r.second, r.third)) {
                    ch.close()
                    ch = r.first
                    bits = r.second
                    jdk = r.third
                    inet = true
                } else {
                    r.first.close() // DF did not take on it either: the dual-stack channel stays (it also reaches IPv6 peers)
                }
            }
            if ((bits > 0 || (bits == 0 && linuxKernel)) && !probeComplete(bits) && probeMissingLogged.compareAndSet(false, true)) {
                printWarning(
                    "kuicksilver: the portable UDP socket has no DF probe mode on every half (bits $bits): DO mode, so a " +
                        "forged ICMP message can end its connections (RFC 9000 section 14.2.1)",
                )
            }
            val gap = dfGap(bits, jdk, inet, apple)
            if (gap != null && dfMissingLogged.compareAndSet(false, true)) {
                printWarning(
                    "kuicksilver: the portable UDP socket cannot set DF on all its traffic ($gap; bits $bits): RFC 9000 " +
                        "section 14 sets it only where possible. QUIC with kuicksilver's TLS needs ksl, which sets it",
                )
            }
            return ch to bits
        }

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
            val (ch, probe) = openWithDf(local)
            val selector: Selector
            try {
                configure(ch)
                ch.bind(local.toJavaAddress())
                ch.configureBlocking(false)
                selector = Selector.open()
            } catch (e: Throwable) {
                ch.close()
                throw e
            }
            ch.register(selector, SelectionKey.OP_READ)
            return NioDatagramIo(ch, selector).also {
                it.dfProbeGranted = probe
                it.enableEcn()
            }
        }
    }
}
