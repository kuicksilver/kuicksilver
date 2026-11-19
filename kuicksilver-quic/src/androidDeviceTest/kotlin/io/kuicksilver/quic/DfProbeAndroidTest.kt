// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ktor.network.sockets.InetSocketAddress
import org.junit.Test
import org.junit.runner.RunWith
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
}
