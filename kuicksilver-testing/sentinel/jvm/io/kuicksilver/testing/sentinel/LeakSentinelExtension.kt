// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing.sentinel

import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.extension.AfterAllCallback
import org.junit.jupiter.api.extension.AfterEachCallback
import org.junit.jupiter.api.extension.BeforeAllCallback
import org.junit.jupiter.api.extension.BeforeEachCallback
import org.junit.jupiter.api.extension.ExtensionContext

/**
 * The leak sentinel ([LeakSentinel]) on the JVM: registered for every test JVM through `META-INF/services` and
 * `junit.jupiter.extensions.autodetection.enabled` (the build sets both). A global extension wraps the class's own
 * `@AfterTest`/`@AfterAll` methods, so the check runs after the test's teardown; a class with `@TestInstance(PER_CLASS)`
 * is checked after all its tests only. A failing test still has its leaks
 * reported, as suppressed exceptions of its own failure.
 */
class LeakSentinelExtension :
    BeforeAllCallback,
    AfterAllCallback,
    BeforeEachCallback,
    AfterEachCallback {
    init {
        LeakSentinel.install(
            sites = System.getenv("KUICKSILVER_LEAK_SITES").let { it != null && it != "0" && it != "false" },
            waitMs = System.getenv("KUICKSILVER_LEAK_WAIT_MS")?.toLongOrNull(),
            slowMs = System.getenv("KUICKSILVER_LEAK_SLOW_MS")?.toLongOrNull(),
            strict = System.getenv("KUICKSILVER_LEAK_STRICT").let { it != null && it != "0" && it != "false" },
        )
    }

    private fun ExtensionContext.store() = getStore(ExtensionContext.Namespace.create(LeakSentinelExtension::class.java, uniqueId))

    override fun beforeAll(context: ExtensionContext) {
        context.store().put(SCOPE, LeakSentinel.begin())
    }

    override fun beforeEach(context: ExtensionContext) {
        context.store().put(SCOPE, LeakSentinel.begin())
    }

    override fun afterEach(context: ExtensionContext) {
        val cls = context.requiredTestClass.name
        // a class whose instance lives for all its tests (`@TestInstance(PER_CLASS)`) shares its fixtures across them by
        // design (a client, a server, their pools): it is checked once, after all of them, as a `per-class` entry would
        val shared = context.testInstanceLifecycle.orElse(null) == TestInstance.Lifecycle.PER_CLASS
        if (shared || LeakSentinel.perClass(cls)) return
        check(context, cls, context.requiredTestMethod.name)
    }

    override fun afterAll(context: ExtensionContext) {
        check(context, context.requiredTestClass.name, null)
    }

    private fun check(
        context: ExtensionContext,
        cls: String,
        test: String?,
    ) {
        val scope = context.store().get(SCOPE, LeakSentinel.Scope::class.java) ?: return
        val leak = LeakSentinel.end(scope, cls, test) ?: return
        val failure = context.executionException.orElse(null)
        if (failure != null) {
            failure.addSuppressed(AssertionError(leak))
            return
        }
        throw AssertionError(leak)
    }

    private companion object {
        const val SCOPE = "scope"
    }
}
