// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.BenchmarkMode
import kotlinx.benchmark.Mode
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.benchmark.TearDown

/**
 * One operation is one whole QUIC connection through [CoreHandshakes] with ksl crypto: a full 1-RTT handshake (X25519, P-256
 * ECDSA, AES-128-GCM), the client's close and both cores closed. ops/s is connections per second for client and server
 * together on one thread (both sides' TLS work is in it; the server's is the larger part: its signature and its context).
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
public class HandshakeBenchmark {
    private lateinit var loop: CoreHandshakes

    @Setup public fun setup() {
        loop = CoreHandshakes()
        check(loop.connection()) { "connection" }
    }
    @TearDown public fun tearDown() { loop.close() }

    @Benchmark public fun connection(): Long {
        check(loop.connection()) { "connection" }
        return loop.completed
    }
}
