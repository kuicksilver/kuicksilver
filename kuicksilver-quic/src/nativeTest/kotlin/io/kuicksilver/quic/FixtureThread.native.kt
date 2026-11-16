// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.native.concurrent.ObsoleteWorkersApi::class)

package io.kuicksilver.quic

internal actual fun fixtureThread(): Any = kotlin.native.concurrent.Worker.current
