// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.Job

/**
 * The server engine's live work for the soak harness (`kuicksilver-soak`): HTTP/3 and HTTP/2 connections it tracks (with
 * the HTTP/2 requests not yet released), the TCP connections its connectors hold (`server.tcpConnections`, counted by
 * `maxTcpConnections`: from accept until the socket is released) and those refused at accept by `maxTcpConnectionsPerIp`
 * since the start (`server.tcpRefusedPerIp`), and the
 * coroutines still running under its HTTP/3 and TCP connection supervisors (handlers, requests and what they launched). A
 * handler that never ends shows up here before it shows up in the heap. The endpoints' own tables are in `QuicResourceProbe`.
 */
@InternalKuicksilverApi
public object KuicksilverServerProbe {
    /** Sizes for [engine]; zeros before it started. */
    public suspend fun snapshot(engine: KuicksilverApplicationEngine): Map<String, Long> {
        var h3 = 0L
        var h3Jobs = 0L
        for (l in engine.h3ListenersForProbe.toList()) {
            h3 += l.size()
            h3Jobs += activeJobs(l.connections)
        }
        val tcpJobs = engine.tcpConnectionsForProbe.toList().sumOf { activeJobs(it) }
        val h2 = engine.h2Live.live()
        return linkedMapOf(
            "server.h3Connections" to h3,
            "server.h3Jobs" to h3Jobs,
            "server.tcpJobs" to tcpJobs,
            "server.h2Connections" to h2.size.toLong(),
            "server.h2Streams" to h2.sumOf { it.openRequests.value.toLong() },
            "server.tcpConnections" to engine.tcpLimitsForProbe.toList().sumOf { it.connections.toLong() },
            "server.tcpRefusedPerIp" to engine.refusedPerIp.value,
        )
    }

    /** Active jobs below [root], [root] itself excluded. */
    private fun activeJobs(root: Job): Long = root.children.sumOf { (if (it.isActive) 1L else 0L) + activeJobs(it) }
}
