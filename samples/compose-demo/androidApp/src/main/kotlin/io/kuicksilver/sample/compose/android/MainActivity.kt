// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose.android

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import io.kuicksilver.sample.compose.AndroidDemoPlatform
import io.kuicksilver.sample.compose.App
import io.kuicksilver.sample.compose.DemoApp

/** One [DemoApp] per process: downloads go on across a rotation, and the clients live as long as the app. */
private object Demo {
    private var app: DemoApp? = null

    @Synchronized
    fun get(context: Context): DemoApp = app ?: DemoApp(AndroidDemoPlatform(context.applicationContext)).also { app = it }
}

/** The demo's only activity: the shared Compose UI over the Android platform (OkHttp as the TCP reference). */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = Demo.get(this)
        setContent { App(app) }
    }
}
