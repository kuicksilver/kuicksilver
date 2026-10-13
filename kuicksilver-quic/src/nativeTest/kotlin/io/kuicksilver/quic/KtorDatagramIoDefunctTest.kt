// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.utils.io.errors.PosixException
import kotlinx.io.IOException
import platform.posix.EAGAIN
import platform.posix.ENOTCONN
import platform.posix.EPIPE
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame

/** The portable Native transport reports ktor's errno failures that mean "socket gone" as [SocketDefunctException]. */
class KtorDatagramIoDefunctTest {
    @Test fun defunctErrnoBecomesSocketDefunct() {
        val e = PosixException.PosixErrnoException(ENOTCONN, "recvfrom")
        val d = KtorDatagramIo.defunctOrNull(e)!!
        assertEquals(ENOTCONN, d.errno)
        assertSame(e, d.cause)
        // also behind a wrapper, as ktor's receive channel closes with one
        val wrapped = IOException("receive failed", PosixException.PosixErrnoException(EPIPE, "sendto"))
        assertEquals(EPIPE, KtorDatagramIo.defunctOrNull(wrapped)!!.errno)
    }

    @Test fun negative_transientErrorsStayAsTheyAre() {
        assertNull(KtorDatagramIo.defunctOrNull(PosixException.PosixErrnoException(EAGAIN, "recvfrom")))
        assertNull(KtorDatagramIo.defunctOrNull(IllegalStateException("closed")))
    }
}
