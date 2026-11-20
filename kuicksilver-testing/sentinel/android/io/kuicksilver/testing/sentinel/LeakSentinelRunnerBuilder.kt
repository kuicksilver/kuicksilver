// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing.sentinel

import org.junit.runner.Runner
import org.junit.runner.notification.RunNotifier
import org.junit.runners.BlockJUnit4ClassRunner
import org.junit.runners.model.FrameworkMethod
import org.junit.runners.model.RunnerBuilder
import org.junit.runners.model.Statement

/**
 * The leak sentinel ([LeakSentinel]) on Android devices: AndroidJUnitRunner builds every test class's runner through this
 * builder (the `runnerBuilder` instrumentation argument the build sets). JUnit 4 has no global extension; the runner it
 * builds checks after each test's `@After` methods and after the class's `@AfterClass` ones. A class with a runner of its
 * own (`@RunWith`), an ignored class (`@Ignore`, which JUnit's own builders skip) or one with nothing this runner can run
 * (no JUnit 4 test method) is left to the next builder: the device-only classes with `@RunWith(AndroidJUnit4::class)` are
 * not checked.
 */
class LeakSentinelRunnerBuilder : RunnerBuilder() {
    init {
        LeakSentinel.install(sites = false, waitMs = null)
    }

    override fun runnerForClass(testClass: Class<*>): Runner? =
        if (!testClass.isAnnotationPresent(org.junit.runner.RunWith::class.java) &&
            !testClass.isAnnotationPresent(org.junit.Ignore::class.java) && // left to JUnit's own builder, which skips it
            hasTestMethods(testClass)
        ) {
            SentinelRunner(testClass)
        } else {
            null
        }

    /**
     * AndroidJUnitRunner hands this builder every class of the test APK, the libraries' too. On Android API 24 and 25 the
     * methods of a class whose signatures name a type the device lacks cannot be listed (`kotlin.io.path.PathsKt` names
     * `java.nio.file.Path`, which arrived in API 26: NoClassDefFoundError); such a class is no test class, and the next
     * builder skips it as androidx's own does ("Failed to scan methods ... skipping").
     */
    private fun hasTestMethods(testClass: Class<*>): Boolean =
        try {
            testClass.methods.any { it.isAnnotationPresent(org.junit.Test::class.java) }
        } catch (_: LinkageError) {
            false
        }

    private class SentinelRunner(
        testClass: Class<*>,
    ) : BlockJUnit4ClassRunner(testClass) {
        private val perClass = LeakSentinel.perClass(testClass.name)

        override fun methodBlock(method: FrameworkMethod): Statement {
            val inner = super.methodBlock(method)
            if (perClass) return inner
            return guarded(inner, testClass.name, method.name)
        }

        override fun classBlock(notifier: RunNotifier): Statement = guarded(super.classBlock(notifier), testClass.name, null)

        private fun guarded(
            inner: Statement,
            cls: String,
            test: String?,
        ) = object : Statement() {
            override fun evaluate() {
                val scope = LeakSentinel.begin()
                try {
                    inner.evaluate()
                } catch (e: Throwable) {
                    LeakSentinel.end(scope, cls, test)?.let { e.addSuppressed(AssertionError(it)) }
                    throw e
                }
                LeakSentinel.end(scope, cls, test)?.let { throw AssertionError(it) }
            }
        }
    }
}
