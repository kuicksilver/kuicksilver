// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.annotation.TargetApi
import android.net.ConnectivityManager
import android.os.Build
import kotlin.concurrent.Volatile

/**
 * The [ConnectivityManager] the application gave the engine through an existing factory
 * (`Http3ConnectionMigration.followDefaultNetwork`, `HttpsRecordSource.followingPrivateDns`): the engine has no `Context`
 * of its own to get one.
 */
internal object AndroidConnectivity {
    @Volatile
    var manager: ConnectivityManager? = null
}

/**
 * The default network's NAT64 prefix as Android knows it (`LinkProperties.getNat64Prefix`, API 30: learnt from a PREF64
 * router advertisement option or by RFC 7050 itself), when the application gave the engine a [ConnectivityManager]
 * ([AndroidConnectivity]); null otherwise, and the engine discovers the prefix by RFC 7050.
 */
internal actual fun platformNat64Prefixes(): List<Pref64>? {
    if (Build.VERSION.SDK_INT < 30) return null
    val connectivity = AndroidConnectivity.manager ?: return null
    return try {
        nat64Prefix(connectivity)?.let { listOf(it) }
    } catch (_: Exception) {
        null // no permission (ACCESS_NETWORK_STATE), a prefix of a length RFC 6052 does not allow
    }
}

@TargetApi(30)
private fun nat64Prefix(connectivity: ConnectivityManager): Pref64? {
    val prefix = connectivity.getLinkProperties(connectivity.activeNetwork)?.nat64Prefix ?: return null
    return Pref64(prefix.address.address, prefix.prefixLength)
}
