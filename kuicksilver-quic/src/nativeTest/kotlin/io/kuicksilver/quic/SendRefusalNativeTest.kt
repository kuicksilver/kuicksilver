// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.utils.io.errors.PosixException
import kotlinx.io.IOException
import platform.posix.EMSGSIZE
import platform.posix.EPIPE
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** ktor's errno failures on Kotlin/Native: EMSGSIZE is a refusal as too large by its errno, whatever the text. */
class SendRefusalNativeTest {
    @Test fun posixEmsgsize() {
        assertTrue(isPlatformEmsgsize(PosixException.PosixErrnoException(EMSGSIZE, "sendto")))
        assertTrue(isPlatformEmsgsize(PosixException.PosixErrnoException(WSAEMSGSIZE, "sendto")))
        assertFalse(isPlatformEmsgsize(PosixException.PosixErrnoException(EPIPE, "sendto")))
        assertTrue(isRefusedAsTooLarge(PosixException.PosixErrnoException(EMSGSIZE, "sendto")))
        assertTrue(isRefusedAsTooLarge(IOException("send failed", PosixException.PosixErrnoException(EMSGSIZE, "sendto"))))
        assertFalse(isRefusedAsTooLarge(PosixException.PosixErrnoException(EPIPE, "sendto")))
    }
}
