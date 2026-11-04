// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/**
 * Runs the steps of a teardown so that each one runs even when an earlier one threw: native buffers, keys and sockets are
 * freed whatever happened to the ones before them. The first failure (or [first], the one that started the teardown) is
 * rethrown by [finish]; later ones are added to it as suppressed.
 */
internal class Releaser(
    private var first: Throwable? = null,
) {
    /** Runs [step]; what it throws is kept for [finish] instead of skipping the steps after it. */
    inline fun release(step: () -> Unit) {
        try {
            step()
        } catch (t: Throwable) {
            note(t)
        }
    }

    fun note(t: Throwable) {
        val f = first
        if (f == null) {
            first = t
        } else if (f !== t) {
            f.addSuppressed(t)
        }
    }

    /** Throws the first failure, if any step (or the cause given at construction) failed. */
    fun finish() {
        first?.let { throw it }
    }
}
