// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Small helpers of Ktor 3.6.0 test utilities (ktor-client-test-base, ktor-test-dispatcher) the vendored tests call.
package io.kuicksilver.ktor.client.contract

import io.ktor.http.content.PartData
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

fun assertArrayEquals(
    message: String,
    expected: ByteArray,
    actual: ByteArray,
) {
    assertTrue(expected.contentEquals(actual), "$message: expected ${expected.size} bytes, got ${actual.size}")
}

suspend fun waitForCondition(
    description: String,
    timeout: Duration = 1000.milliseconds,
    condition: suspend () -> Boolean,
) {
    withTimeoutOrNull(timeout) { while (!condition()) delay(10.milliseconds) } ?: fail("Timed out waiting for $description")
}

fun Job.getActiveChildren(): Sequence<Job> = children.filter { it.isActive }

suspend fun List<PartData>.makeString(): String = buildString { this@makeString.forEach { append(it.makeString()) } }
