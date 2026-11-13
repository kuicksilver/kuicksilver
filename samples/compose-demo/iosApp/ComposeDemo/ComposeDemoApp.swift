// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import ComposeApp
import SwiftUI
import UIKit

/// The SwiftUI shell around the shared Compose UI (`MainViewController` in composeApp/src/iosMain).
@main
struct ComposeDemoApp: App {
    var body: some Scene {
        WindowGroup {
            ComposeView().ignoresSafeArea(.keyboard)
        }
    }
}

struct ComposeView: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UIViewController {
        MainViewControllerKt.MainViewController()
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}
}
