// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import androidx.compose.ui.window.ComposeUIViewController
import platform.UIKit.UIViewController

/** One [DemoApp] per process: the clients and the running downloads outlive the view controller. */
private val demo: DemoApp by lazy { DemoApp(IosDemoPlatform()) }

/** The demo's UI for the SwiftUI app (iosApp/ComposeDemo/ComposeDemoApp.swift): `MainViewControllerKt.MainViewController()`. */
fun MainViewController(): UIViewController = ComposeUIViewController { App(demo) }
