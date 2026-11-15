// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.wire.ConnectionId
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

class TowardsRingEquivalenceTest {
    /** The pre-change implementation, verbatim. */
    private class Old {
        private val towardsIp = arrayOfNulls<AddressClass.IpKey>(4)
        private val towardsPort = IntArray(4)
        private var towardsNext = 0

        fun noteSentTowards(
            ip: AddressClass.IpKey,
            port: Int,
        ) {
            for (i in 0 until 4) if (towardsPort[i] == port && towardsIp[i] == ip) return
            towardsIp[towardsNext] = ip
            towardsPort[towardsNext] = port
            towardsNext = (towardsNext + 1) % 4
        }

        fun sentOnlyTowards(
            ip: AddressClass.IpKey,
            port: Int,
        ): Boolean {
            for (i in 0 until 4) if (towardsIp[i] != null && (towardsPort[i] != port || towardsIp[i] != ip)) return false
            return true
        }

        fun sentTowards(
            ip: AddressClass.IpKey,
            port: Int,
        ): Boolean {
            for (i in 0 until 4) if (towardsPort[i] == port && towardsIp[i] == ip) return true
            return false
        }
    }

    @Test
    fun randomizedEquivalence() {
        var checks = 0L
        for (seed in 0 until 20_000) {
            val rnd = Random(seed)
            val nIps = 1 + rnd.nextInt(4)
            val nPorts = 1 + rnd.nextInt(4)
            // ports include 0, the old array's default, to probe the empty-slot case
            val ports = IntArray(nPorts) { if (it == 0) 0 else 443 + it }

            // fresh IpKey instances each time: equality must be by content
            fun ip(i: Int) = AddressClass.IpKey(byteArrayOf(10, 0, 0, i.toByte()))
            val old = Old()
            val new = ConnectionIdManager.Peer(1, ConnectionId(byteArrayOf(1)), null)
            val steps = rnd.nextInt(30)

            fun compare(step: Int) {
                for (a in 0..nIps) {
                    for (p in ports) {
                        assertEquals(old.sentTowards(ip(a), p), new.sentTowards(ip(a), p), "seed $seed step $step sentTowards $a:$p")
                        assertEquals(old.sentOnlyTowards(ip(a), p), new.sentOnlyTowards(ip(a), p), "seed $seed step $step only $a:$p")
                        checks += 2
                    }
                }
            }
            compare(-1)
            for (s in 0 until steps) {
                val a = rnd.nextInt(nIps)
                val p = ports[rnd.nextInt(nPorts)]
                old.noteSentTowards(ip(a), p)
                new.noteSentTowards(ip(a), p)
                compare(s)
            }
        }
        println("TowardsRing equivalence checks: $checks")
    }
}
