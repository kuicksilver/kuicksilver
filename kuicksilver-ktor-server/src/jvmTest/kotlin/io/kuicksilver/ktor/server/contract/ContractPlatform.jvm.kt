// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.contract

import org.junit.jupiter.api.Assumptions.assumeTrue

/** Ktor's markers on the running `@Test` method, found through the stack (Ktor's EngineTestBaseJvm does the same). */
internal actual fun EngineTestBase<*, *>.testMarkers(): Set<String> {
    val names =
        Thread
            .currentThread()
            .stackTrace
            .map { it.methodName }
            .toSet()
    val method =
        generateSequence<Class<*>>(javaClass) { it.superclass }
            .flatMap { it.declaredMethods.asSequence() }
            .firstOrNull { it.name in names && it.isAnnotationPresent(kotlin.test.Test::class.java) }
            ?: return emptySet()
    return buildSet {
        if (method.isAnnotationPresent(EngineTestBase.Http1Only::class.java)) add("Http1Only")
        if (method.isAnnotationPresent(EngineTestBase.Http2Only::class.java)) add("Http2Only")
    }
}

internal actual fun skipTest(reason: String) = assumeTrue(false, reason)

internal actual val vendoredJvmContentSuite: Boolean = true
