// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PacketBatch
import kotlinx.coroutines.delay
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.time.Duration

/**
 * An engine endpoint's socket on a network that cuts UDP flows: once [cut], [n] more datagram batches pass each way,
 * then nothing, until [heal]. [receiveDelay] holds every received batch that long before the endpoint sees it (a path
 * with a longer RTT; batches that wait behind one another add up).
 */
@OptIn(ExperimentalAtomicApi::class)
internal class FaultyIo(
    private val d: DatagramIo,
) : DatagramIo by d {
    private val sendLeft = AtomicInt(Int.MAX_VALUE)
    private val receiveLeft = AtomicInt(Int.MAX_VALUE)

    @kotlin.concurrent.Volatile var receiveDelay: Duration = Duration.ZERO

    fun cut(n: Int) {
        sendLeft.store(n)
        receiveLeft.store(n)
    }

    fun heal() = cut(Int.MAX_VALUE)

    private fun pass(
        left: AtomicInt,
        count: Int,
    ): Boolean {
        while (true) {
            val l = left.load()
            if (l == Int.MAX_VALUE) return true
            if (l < count) {
                left.store(0)
                return false
            }
            if (left.compareAndSet(l, l - count)) return true
        }
    }

    override suspend fun send(batch: PacketBatch): Int = if (pass(sendLeft, batch.count)) d.send(batch) else batch.count

    override fun trySend(batch: PacketBatch): Int = if (pass(sendLeft, batch.count)) d.trySend(batch) else batch.count

    override suspend fun receive(into: PacketBatch): Int {
        while (true) {
            val before = into.count
            val n = d.receive(into)
            if (n > 0 && receiveDelay.isPositive()) delay(receiveDelay)
            if (n <= 0 || pass(receiveLeft, n)) return n
            into.count = before // dropped on the way
        }
    }
}

/** Every [FaultyIo] an engine opened, and the faults for those it opens later (an endpoint bound at the first HTTP/3 attempt). */
@OptIn(ExperimentalAtomicApi::class)
internal class FaultyIos {
    val opened = AtomicReference(emptyList<FaultyIo>())

    @kotlin.concurrent.Volatile private var cutAt: Int? = null

    @kotlin.concurrent.Volatile private var delay: Duration = Duration.ZERO

    fun cut(n: Int = 0) {
        cutAt = n
        opened.load().forEach { it.cut(n) }
    }

    fun heal() {
        cutAt = null
        opened.load().forEach { it.heal() }
    }

    fun delayReceived(d: Duration) {
        delay = d
        opened.load().forEach { it.receiveDelay = d }
    }

    suspend fun open(local: InetSocketAddress): DatagramIo =
        FaultyIo(DatagramIo.open(local)).also { f ->
            cutAt?.let { f.cut(it) }
            f.receiveDelay = delay
            opened.update { it + f }
        }
}
