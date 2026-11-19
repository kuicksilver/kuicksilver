// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.KslSocketDf
import java.nio.channels.DatagramChannel

/** Through `ksl` ([KslSocketDf]: Linux and Windows; Apple has no modes, 0); -1 without the library. Loads `ksl`. */
internal actual fun dfProbe(ch: DatagramChannel): Int = KslSocketDf.apply(ch)

internal actual fun dfModeOf(
    ch: DatagramChannel,
    family: Int,
): Int = KslSocketDf.mode(ch, family)

internal actual fun localizedEmsgsizeText(): String? = KslSocketDf.emsgsizeText()
