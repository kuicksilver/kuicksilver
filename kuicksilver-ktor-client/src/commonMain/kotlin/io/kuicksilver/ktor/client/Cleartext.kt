// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/**
 * Whether the platform's network security policy lets the engine talk to [host] in cleartext (`http://`, `ws://`). On
 * Android this is the app's Network Security Configuration (`NetworkSecurityPolicy.isCleartextTrafficPermitted`, which
 * is false by default from targetSdk 28), as OkHttp, HttpURLConnection and Cronet honour it; elsewhere always true.
 */
internal expect fun platformCleartextPermitted(host: String): Boolean

/** The refusal of a cleartext request, worded as OkHttp's (an IOException, as any connection failure). */
internal fun cleartextNotPermitted(host: String): kotlinx.io.IOException =
    kotlinx.io.IOException("CLEARTEXT communication to $host not permitted by network security policy")
