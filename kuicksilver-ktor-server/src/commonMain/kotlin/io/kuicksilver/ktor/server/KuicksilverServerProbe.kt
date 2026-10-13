// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.Job

/**
 * The server engine's live work for the soak harness (`kuicksilver-soak`): HTTP/3 connections its listeners track, and the
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
        return linkedMapOf("server.h3Connections" to h3, "server.h3Jobs" to h3Jobs, "server.tcpJobs" to tcpJobs)
    }

    /** Active jobs below [root], [root] itself excluded. */
    private fun activeJobs(root: Job): Long = root.children.sumOf { (if (it.isActive) 1L else 0L) + activeJobs(it) }
}
