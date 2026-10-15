// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** Open descriptors (POSIX) or handles (Windows) of this process: a leak check counts the difference. */
internal expect fun openHandleCount(): Int
