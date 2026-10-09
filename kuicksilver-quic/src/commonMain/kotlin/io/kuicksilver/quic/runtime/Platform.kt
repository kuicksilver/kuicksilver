// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

/** True where the portable DatagramIo can serve a QUIC server (JVM/Android); Native servers wait for the accelerated transport (K3). */
internal expect val portableServerSupported: Boolean
