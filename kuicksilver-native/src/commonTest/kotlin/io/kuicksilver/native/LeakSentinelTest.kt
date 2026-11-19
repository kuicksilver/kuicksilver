// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.testing.sentinel.LeakAllowEntry
import io.kuicksilver.testing.sentinel.LeakSentinel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * The leak sentinel itself (docs/process.md, "The leak sentinel"): it is installed in every test run, names what a test
 * left open, waits for a close that comes after the test, and an allow entry tolerates only the kinds it names. The
 * negative controls leak on purpose inside their own scope and close what they leaked before they end.
 */
class LeakSentinelTest {
    private val short = 200.milliseconds

    @Test fun negative_anObjectLeftOpenIsNamedWithItsKindAndCount() {
        val scope = LeakSentinel.begin()
        val a = LeakRegistry.open("test.thing")
        val b = LeakRegistry.open("test.thing")
        try {
            val leak = assertNotNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
            assertContains(leak, "leak sentinel: C.t left open")
            assertContains(leak, "test.thing x2")
        } finally {
            LeakRegistry.close(a)
            LeakRegistry.close(b)
        }
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
    }

    @Test fun negative_aNativeKeyLeftOpenIsCounted() {
        KslLoader.ensureLoaded()
        val scope = LeakSentinel.begin()
        val key = Ksl.keyRandom(KslConst.EKEY_TOKEN)
        try {
            assertContains(assertNotNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short)), "ksl.key x1")
        } finally {
            Ksl.keyFree(key)
        }
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
    }

    /** Opened before the scope began: a class's fixture, not the test's. */
    @Test fun anObjectOpenedBeforeTheTestIsNotItsLeak() {
        val fixture = LeakRegistry.open("test.fixture")
        try {
            val scope = LeakSentinel.begin()
            assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
        } finally {
            LeakRegistry.close(fixture)
        }
    }

    /** A close on another thread, before or while the sentinel waits (asynchronous teardown), is no leak: the wait wakes on it. */
    @OptIn(DelicateCoroutinesApi::class)
    @Test
    fun aCloseAfterTheTestIsWaitedFor() {
        val scope = LeakSentinel.begin()
        val id = LeakRegistry.open("test.async")
        val go = CompletableDeferred<Unit>()
        GlobalScope.launch(Dispatchers.Default) {
            go.await()
            LeakRegistry.close(id)
        }
        go.complete(Unit)
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList()))
    }

    @Test fun negative_anAllowEntryToleratesOnlyItsKinds() {
        val scope = LeakSentinel.begin()
        val allowed = LeakRegistry.open("test.allowed")
        val other = LeakRegistry.open("test.other")
        try {
            val allow = listOf(LeakAllowEntry("allow", "C.t", listOf("test.allowed")))
            val leak = assertNotNull(LeakSentinel.end(scope, "C", "t", allow = allow, wait = short))
            assertContains(leak, "test.other x1")
            assertEquals(false, "test.allowed" in leak)
            LeakRegistry.close(other)
            assertNull(LeakSentinel.end(scope, "C", "t", allow = allow, wait = short))
            // another test of the class is not covered by an entry naming one test; the class's own check is
            assertNotNull(LeakSentinel.end(scope, "C", "u", allow = allow, wait = short))
            assertNull(LeakSentinel.end(scope, "C", null, allow = allow, wait = short))
        } finally {
            LeakRegistry.close(allowed)
            LeakRegistry.close(other)
        }
    }

    /** A close that comes only after the sentinel looked is waited for; slow, it is reported, and strict mode fails on it. */
    @OptIn(DelicateCoroutinesApi::class)
    @Test
    fun negative_aSlowCloseFailsInStrictMode() {
        for (strict in listOf(false, true)) {
            val scope = LeakSentinel.begin()
            val id = LeakRegistry.open("test.slow")
            val go = CompletableDeferred<Unit>()
            GlobalScope.launch(Dispatchers.Default) {
                go.await()
                LeakRegistry.close(id)
            }
            val r =
                LeakSentinel.end(scope, "C", "t", allow = emptyList(), slow = Duration.ZERO, strict = strict, afterFirstLookForTest = {
                    go.complete(Unit)
                })
            if (strict) {
                assertContains(assertNotNull(r), "leak sentinel: C.t took")
                assertContains(r, "to close test.slow x1")
            } else {
                assertNull(r, "a slow close that ended is only reported")
            }
        }
    }

    /** A test that frees a native object it did not make is said so: such a drop could hide a leak of the same kind. */
    @Test fun negative_aNativeObjectFreedThatTheTestDidNotMakeIsSaid() {
        KslLoader.ensureLoaded()
        val key = Ksl.keyRandom(KslConst.EKEY_TOKEN) // an earlier test's, say
        val scope = LeakSentinel.begin()
        Ksl.keyFree(key)
        assertContains(assertNotNull(LeakSentinel.freedBefore(scope)), "ksl.key -1")
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short), "not a failure")
    }
}
