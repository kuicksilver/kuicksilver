// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The redirect check ([isSafeToRedirect]) runs on every invalid GET or HEAD target before the client is authenticated,
 * so its work must grow linearly with the target: dot-segment removal (RFC 3986 section 5.2.4) that copies the rest of
 * the path at every step is quadratic, about 16 MB of copying for one 8 KiB `/./././...^` target. The work is counted,
 * not timed, so the test is the same on every platform and runner.
 */
class SafeRedirectTest {
    /**
     * The characters dot-segment removal copies, counted through its test hook: at most twice the path's length for
     * every shape of an 8 KiB target, so the work is linear. Copying the rest of the path at every step, as the
     * algorithm's text does, copies about n^2 / 4 characters for `/./././...` (16 million for 8 KiB).
     */
    @Test fun negative_dotSegmentRemovalIsLinear() {
        for (path in listOf(
            "/" + "./".repeat(4_096),
            "/a".repeat(4_096),
            "/" + "../".repeat(2_730),
            "/" + "a/../".repeat(1_638),
            "/" + "/".repeat(8_190),
            "/" + "a".repeat(8_190),
        )) {
            var copied = 0L
            removeDotSegments(path) { copied += it }
            assertTrue(copied <= 2L * path.length, "${path.take(8)}...: $copied characters copied for ${path.length}")
        }
    }

    /** The decisions stay those of RFC 3986 section 5.2.4 (the rows of negative_redirectNeverLeavesTheServer, and more). */
    @Test fun dotSegmentsAreRemovedAsRfc3986Says() {
        for (t in listOf("//e/^", "/.//e/^", "/a/..//e/^", "/a/../../%2Fe/^", "/a\\..\\..\\/e/^", "/%2E%2E//e^", "//", "/x/..//")) {
            assertFalse(isSafeToRedirect(t), t)
        }
        for (t in listOf("/^", "/a/../b^", "/./a//b^", "/..^", "/x/..", "/?//e^", "/%2e./x//^", "/a/.")) {
            assertTrue(isSafeToRedirect(t), t)
        }
    }
}
