// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import java.lang.management.ManagementFactory

/** The receiver's thread found by its stack (it stays in `SocketDispatcher.receive` for the socket's life), timed by the JVM. */
internal actual class ReceiverCpu private constructor(private val id: Long) {
    actual fun nanos(): Long = threads.getThreadCpuTime(id)

    actual companion object {
        private val threads = ManagementFactory.getThreadMXBean()

        actual fun find(): ReceiverCpu? {
            if (!threads.isThreadCpuTimeSupported) return null
            if (!threads.isThreadCpuTimeEnabled) threads.isThreadCpuTimeEnabled = true
            val receivers = Thread.getAllStackTraces().filter { (_, stack) ->
                stack.any { it.className.startsWith("io.kuicksilver.quic.runtime.SocketDispatcher") && it.methodName.startsWith("receive") }
            }.keys
            // one server endpoint with one main socket: one receiver, or none (one loop, or the kernel balances the port)
            return receivers.singleOrNull()?.let { ReceiverCpu(it.threadId()) }
        }

        actual fun note(cpu: ReceiverCpu?): String =
            if (cpu != null) "ThreadMXBean" else "no receiver thread: one loop, or kernel mode (a socket per loop)"
    }
}
