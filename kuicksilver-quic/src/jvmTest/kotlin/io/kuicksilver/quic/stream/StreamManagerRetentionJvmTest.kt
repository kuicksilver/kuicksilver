// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.tls.TlsRole
import java.lang.reflect.Modifier
import java.util.IdentityHashMap
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Soak regression (0.2.0, Linux arm64 Native heap creep): a connection must not keep anything per peer stream once the stream
 * is finished. StreamManager appended every peer-opened stream id to a list nothing drained, so the soak's one long-lived
 * server HTTP/3 connection kept a boxed id per request. This test does not depend on a probe naming that list: it walks
 * every field of the manager (and of the kuicksilver objects it holds) by reflection and adds up the size of each
 * collection, map and array, after 100 and after 3000 finished peer streams; the totals must not grow with the count.
 */
class StreamManagerRetentionJvmTest {
    @Test fun finishedPeerStreamsRetainNothingPerStream() {
        val few = retainedAfter(100)
        val many = retainedAfter(3000)
        assertTrue(
            many - few <= SLACK,
            "StreamManager containers grow with finished peer streams: $few after 100, $many after 3000",
        )
    }

    /** Opens, drains and finishes [n] client unidirectional streams on a server manager, then sums its containers. */
    private fun retainedAfter(n: Int): Long {
        val m =
            StreamManager(
                TlsRole.Server,
                QuicConfig.Default,
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 1000, 1000),
            )
        m.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 1000, 1000)
        val buf = ByteArray(64)
        repeat(n) { i ->
            val id = 4L * i + 2
            val b = PacketBuffer.of(ByteArray(11))
            try {
                m.onStream(id, 0, b, 0, 10, true)
            } finally {
                b.close()
            }
            while (m.read(id, buf, 0, buf.size) >= 0) {
                // to the end: the stream finishes and is forgotten
            }
            m.events.clear()
            while (m.takeControlFrame() != null) {
                // MAX_STREAMS credit, as the connection would send it
            }
        }
        return containerSizes(m, IdentityHashMap(), 0)
    }

    /** Sum of the sizes of every Collection, Map and array reachable through fields of kuicksilver objects, up to [MAX_DEPTH]. */
    private fun containerSizes(
        o: Any?,
        seen: IdentityHashMap<Any, Unit>,
        depth: Int,
    ): Long {
        if (o == null || seen.put(o, Unit) != null) return 0
        when (o) {
            is Collection<*> -> return o.size.toLong()
            is Map<*, *> -> return o.size.toLong()
            is ByteArray -> return o.size.toLong()
            is LongArray -> return o.size.toLong()
            is IntArray -> return o.size.toLong()
            is BooleanArray -> return o.size.toLong()
            is Array<*> -> return o.size.toLong()
        }
        if (depth >= MAX_DEPTH || !o.javaClass.name.startsWith("io.kuicksilver.")) return 0
        var total = 0L
        var c: Class<*>? = o.javaClass
        while (c != null && c.name.startsWith("io.kuicksilver.")) {
            for (f in c.declaredFields) {
                if (Modifier.isStatic(f.modifiers) || f.type.isPrimitive) continue
                f.isAccessible = true
                total += containerSizes(f.get(o), seen, depth + 1)
            }
            c = c.superclass
        }
        return total
    }

    private companion object {
        const val MAX_DEPTH = 4

        /** Containers that legitimately differ by a few slots between runs (a scheduler's ring, amortised arrays). */
        const val SLACK = 16L
    }
}
