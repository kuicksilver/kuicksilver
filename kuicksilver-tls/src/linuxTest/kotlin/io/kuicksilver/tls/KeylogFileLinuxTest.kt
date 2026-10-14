// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import kotlinx.cinterop.ExperimentalForeignApi
import platform.posix.getpid
import platform.posix.mkfifo
import platform.posix.unlink
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

/** `keylogFile` on Linux: a FIFO at the path never blocks (security review 2026-10-14, finding 6; threat model 3.7). */
class KeylogFileLinuxTest {
    private fun tmp(name: String): String = "/tmp/ksl-keylog-$name-${getpid()}.txt".also { unlink(it) }

    @Test fun negative_keylogFileRefusesFifo() {
        val fifo = tmp("fifo")
        assertEquals(0, mkfifo(fifo, 0x180u))
        try {
            assertFails { keylogFile(fifo) }
        } finally {
            unlink(fifo)
        }
    }

    @Test fun negative_keylogFifoSwappedInLaterDoesNotBlock() {
        val path = tmp("swap")
        val sink = keylogFile(path)
        unlink(path)
        assertEquals(0, mkfifo(path, 0x180u))
        try {
            sink.log("X")
        } finally {
            unlink(path)
        }
    }
}
