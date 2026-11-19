// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalNativeApi::class, ExperimentalForeignApi::class)

package io.kuicksilver.testing.sentinel

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.getenv
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.internal.test.GeneratedSuites
import kotlin.native.internal.test.TestCase
import kotlin.native.internal.test.TestSuite
import kotlin.native.internal.test.testLauncherEntryPoint
import kotlin.system.exitProcess

/**
 * The entry point of every Kotlin/Native test executable (the build passes it with `-e`): the leak sentinel
 * ([LeakSentinel]) around each test and each class, then Kotlin's own test launcher. kotlin.test on Native has no global
 * extension, so each suite the compiler generated is replaced by one that checks after each test's `@AfterTest` methods,
 * and after all of a class's tests in one more test of the class, `leakSentinelClassCheck`; names, filters and loggers
 * are the launcher's as before.
 */
fun leakSentinelTestMain(args: Array<String>) {
    LeakSentinel.install(
        sites = getenv("KUICKSILVER_LEAK_SITES")?.toKString().let { it != null && it != "0" && it != "false" },
        waitMs = getenv("KUICKSILVER_LEAK_WAIT_MS")?.toKString()?.toLongOrNull(),
        slowMs = getenv("KUICKSILVER_LEAK_SLOW_MS")?.toKString()?.toLongOrNull(),
        strict = getenv("KUICKSILVER_LEAK_STRICT")?.toKString().let { it != null && it != "0" && it != "false" },
    )
    val suites = GeneratedSuites.suites
    val wrapped = suites.map { SentinelSuite(it) }
    suites.clear()
    suites.addAll(wrapped)
    val exitCode = testLauncherEntryPoint(args)
    if (exitCode != 0) exitProcess(exitCode)
}

private class SentinelSuite(
    private val inner: TestSuite,
) : TestSuite by inner {
    private var classScope: LeakSentinel.Scope? = null
    private val perClass = LeakSentinel.perClass(inner.name)

    /**
     * The suite's own tests, then its class check as one more test: the launcher does not catch a failure of a suite's
     * after-class hook (it ends the whole executable), and kotlin.test has no after-class methods there anyway.
     */
    override val testCases: Map<String, TestCase> =
        inner.testCases.mapValues { (_, t) -> SentinelCase(t, this) } + (CLASS_CHECK to ClassCheck(this))

    override val size: Int get() = testCases.size

    override fun doBeforeClass() {
        classScope = LeakSentinel.begin()
        inner.doBeforeClass()
    }

    private class SentinelCase(
        private val inner: TestCase,
        override val suite: SentinelSuite,
    ) : TestCase by inner {
        override fun run() {
            val scope = LeakSentinel.begin()
            var failure: Throwable? = null
            try {
                inner.run()
            } catch (e: Throwable) {
                failure = e
            }
            val leak = if (suite.perClass) null else LeakSentinel.end(scope, suite.name, inner.name)
            if (failure != null) {
                leak?.let { failure.addSuppressed(AssertionError(it)) }
                throw failure
            }
            if (leak != null) throw AssertionError(leak)
        }
    }

    /** What the class left open, after all its tests; ignored when all of them are (the suite does not run then). */
    private class ClassCheck(
        override val suite: SentinelSuite,
    ) : TestCase {
        override val name: String get() = CLASS_CHECK
        override val ignored: Boolean =
            suite.inner.testCases.values
                .all { it.ignored }

        override fun doBefore() = Unit

        override fun doAfter() = Unit

        override fun doRun() {
            val scope = suite.classScope ?: return
            LeakSentinel.end(scope, suite.inner.name, null)?.let { throw AssertionError(it) }
        }
    }

    private companion object {
        /** The name the class check is reported under. */
        const val CLASS_CHECK = "leakSentinelClassCheck"
    }
}
