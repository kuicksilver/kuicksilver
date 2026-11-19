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
            val n =
                try {
                    channel.send(view, javaOf(a))
                } catch (e: java.net.SocketException) {
                    // DF in DO mode: a cached path MTU below QUIC's floor is a failed path, not a lost datagram
                    if (isMessageTooLong(e) && batch.length(i) <= PATH_MTU_FLOOR) throw PathMtuRefusedException(batch.length(i), e)
                    throw e
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

        /**
         * EMSGSIZE / WSAEMSGSIZE as the JDK reports a send's: "Message too long" (Linux strerror; Android adds "EMSGSIZE"), and
         * on Windows the JDK's own text for WSAEMSGSIZE (net_util_md.c: "The message is larger than the maximum supported by the
         * underlying transport").
         */
        internal fun isMessageTooLong(e: java.net.SocketException): Boolean {
            val m = e.message ?: return false
            return m.contains("Message too long", ignoreCase = true) || m.contains("EMSGSIZE") ||
                m.contains("larger than the maximum supported by the underlying transport", ignoreCase = true)
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

        /**
         * RFC 9000 section 14: "UDP datagrams MUST NOT be fragmented at the IP layer. In IPv4, the Don't Fragment (DF) bit MUST
         * be set if possible"; section 14.2.1: an endpoint "MUST ignore an ICMP message that claims the PMTU has decreased
         * below QUIC's smallest allowed maximum datagram size". DF is always set. Probe mode (`IP_PMTUDISC_PROBE` /
         * `IPV6_PMTUDISC_PROBE`, through `ksl` on the JVM and `android.system.Os` on Android: [dfProbe]) meets both: no
         * fragmentation and no path MTU cache an ICMP message could lower. Where a half refuses probe mode (`ksl` present but
         * the system says no: a seccomp filter, gVisor, Windows without the option) it gets DO mode, and where nothing could
         * be asked (the JVM without `ksl`; Apple, which has only IP_DONTFRAG) the JDK's `IP_DONTFRAGMENT` (JDK 19 and later),
         * DO mode on Linux and Windows. DO mode never fragments either, but there section 14.2.1 is a limitation the system
         * imposes: a forged ICMP message claiming less than 1200 makes it refuse sends to that peer (Linux EMSGSIZE for ten
         * minutes; Windows WSAEMSGSIZE, verified on a Windows 11 VM against a non-loopback peer, loopback unaffected). Such a
         * refusal of a datagram of at most 1200 bytes is [PathMtuRefusedException]: the connection ends with no viable path
         * (an HTTP/3 client falls back to TCP) instead of losing datagrams until its idle timeout. On a dual-stack channel
         * without `ksl` the JDK's option covers the IPv6 half only; IPv4-mapped traffic keeps the system's default. Real QUIC
         * on the JVM needs `ksl` anyway (its TLS), so the paths without probe mode matter only where the system refuses it or
         * with a third-party `QuicCrypto`. This socket's datagrams stay within 1200 bytes, so PMTUD stays off (`df`
         * capability false); with probe mode it could run here later. Returns the [dfProbe] bits.
         */
        private fun setDontFragment(ch: DatagramChannel): Int {
            val bits = dfProbe(ch)
            if ((bits > 0 || (bits == 0 && linuxKernel)) && !probeComplete(bits) && probeMissingLogged.compareAndSet(false, true)) {
                printWarning(
                    "kuicksilver: the portable UDP socket has no DF probe mode on every half (bits $bits): DO mode, so a " +
                        "forged ICMP message can end its connections (RFC 9000 section 14.2.1)",
                )
            }
            if (!usesJdkDontFragment(bits)) return bits
            val opt = dontFragmentOption() ?: return bits
            try {
                if (opt in ch.supportedOptions()) ch.setOption(opt, true)
            } catch (_: java.io.IOException) {
            } catch (_: UnsupportedOperationException) {
            }
            return bits
        }

        /** How long a send waits for room in a full socket buffer before the rest of its batch is lost. */
        private const val WRITE_WAIT_MS = 5L

        /** [configure] runs on the unbound channel before `bind` (Android binds it to a network); if anything throws, the channel is closed. */
        fun open(
            local: InetSocketAddress,
            configure: (DatagramChannel) -> Unit = {},
        ): NioDatagramIo {
            val ch = DatagramChannel.open()
            val selector: Selector
            val probe: Int
            try {
                ch.setOption(StandardSocketOptions.SO_RCVBUF, 8 shl 20)
                ch.setOption(StandardSocketOptions.SO_SNDBUF, 8 shl 20)
                probe = setDontFragment(ch)
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
