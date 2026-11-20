// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ktor.network.sockets.InetSocketAddress
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * RFC 9000 sections 14 and 14.2.1 on Android: the portable socket's DF is in probe mode on both halves of a dual-stack channel
 * (`IP_MTU_DISCOVER` and `IPV6_MTU_DISCOVER` = PROBE through `android.system.Os`), so a forged ICMP message can neither make
 * the kernel refuse sends nor fragment them. Wildcard bind, as a client's: the channel is AF_INET6.
 */
@RunWith(AndroidJUnit4::class)
class DfProbeAndroidTest {
    @Test fun portableSocketIsInProbeModeOnBothHalves() {
        val io = NioDatagramIo.open(InetSocketAddress("0.0.0.0", 0))
        try {
            val bits = io.dfProbeGranted
            Log.i("kuicksilver", "portable socket DF bits: $bits")
            assertTrue(bits and DF_INET6 != 0, "a dual-stack channel: $bits")
            assertEquals(DF_INET6 or DF_V4 or DF_V6, bits, "probe mode on both halves, no DO fallback")
            assertTrue(probeComplete(bits))
        } finally {
            io.close()
        }
    }

    /**
     * The probe only borrows the channel's descriptor: the channel still binds, sends and receives after it. Up to API 28
     * `ParcelFileDescriptor.fromDatagramSocket` wraps the channel's own descriptor instead of a duplicate (the duplicate came
     * with API 29), so closing that wrapper closed the channel ("Bad file descriptor" on API 24). Red before on API 24.
     */
    @Test fun theProbeLeavesTheChannelOpen() {
        val ch = DatagramChannel.open()
        try {
            val bits = dfProbe(ch)
            ch.bind(java.net.InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
            ch.send(ByteBuffer.wrap(byteArrayOf(7)), ch.localAddress)
            val got = ByteBuffer.allocate(4)
            ch.receive(got)
            assertEquals(1, got.position(), "a datagram to itself after the probe (bits $bits)")
            assertTrue(ch.isOpen)
        } finally {
            ch.close()
        }
    }
}
