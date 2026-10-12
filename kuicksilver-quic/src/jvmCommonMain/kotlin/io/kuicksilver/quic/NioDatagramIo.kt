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
 * at the socket buffer one datagram at a time.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class NioDatagramIo private constructor(
    private val channel: DatagramChannel,
    private val selector: Selector,
) : DatagramIo {
    override val localAddress: InetSocketAddress =
        (channel.localAddress as java.net.InetSocketAddress).let {
            InetSocketAddress(it.address.hostAddress, it.port)
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
        val k = InetSocketAddress(a.address.hostAddress, a.port)
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

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        val immediate = drain(into)
        if (immediate > 0) return immediate
        return runInterruptible(Dispatchers.IO) {
            while (true) {
                if (!channel.isOpen) throw java.io.IOException("datagram channel closed")
                selector.select()
                selector.selectedKeys().clear()
                val n = drain(into)
                if (n > 0) return@runInterruptible n
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
            if (channel.send(view, javaOf(a)) == 0 && batch.length(i) > 0) return i // a non-blocking channel takes all or nothing
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
        /** How long a send waits for room in a full socket buffer before the rest of its batch is lost. */
        private const val WRITE_WAIT_MS = 5L

        fun open(local: InetSocketAddress): NioDatagramIo {
            val ch = DatagramChannel.open()
            ch.setOption(StandardSocketOptions.SO_RCVBUF, 8 shl 20)
            ch.setOption(StandardSocketOptions.SO_SNDBUF, 8 shl 20)
            ch.bind(local.toJavaAddress())
            ch.configureBlocking(false)
            val selector = Selector.open()
            ch.register(selector, SelectionKey.OP_READ)
            return NioDatagramIo(ch, selector).also { it.enableEcn() }
        }
    }
}
