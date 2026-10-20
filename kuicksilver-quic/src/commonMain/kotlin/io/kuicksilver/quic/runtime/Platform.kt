// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

/** True where the portable DatagramIo can serve a QUIC server (JVM/Android); Native servers wait for the accelerated transport (K3). */
internal expect val portableServerSupported: Boolean

/** True where a `poll` of 1 ms waits about 1 ms; false on Windows, whose `WSAPoll` waits whole timer ticks (15.6 ms by default). */
internal expect val millisecondPollWaits: Boolean
