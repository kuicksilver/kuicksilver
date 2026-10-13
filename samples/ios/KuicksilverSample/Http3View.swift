// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Shared
import SwiftUI

/// HTTP/3 GET of a configurable URL.
struct Http3View: View {
    @EnvironmentObject private var model: AppModel
    @State private var url = "https://cloudflare-quic.com/"
    @State private var running: SampleTask?
    @State private var result: HttpResult?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Request") {
                    TextField("https://host[:port]/path", text: $url)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button(running == nil ? "GET" : "Cancel") { running == nil ? get() : cancel() }
                }
                if let result {
                    Section("Response") {
                        LabeledContent("Status", value: "\(result.status)")
                        LabeledContent("Server", value: result.remote)
                        LabeledContent("Time", value: "\(result.elapsedMs) ms")
                        LabeledContent("Smoothed RTT", value: String(format: "%.1f ms", result.smoothedRttMs))
                        LabeledContent("Body", value: "\(result.bodyBytes) bytes")
                    }
                    Section("Headers") { Text(result.headers).font(.caption.monospaced()).textSelection(.enabled) }
                    Section("Body (first 4 KiB)") { Text(result.bodyPreview).font(.caption.monospaced()).textSelection(.enabled) }
                }
                if let error { Section("Error") { Text(error).foregroundStyle(.red).textSelection(.enabled) } }
            }
            .navigationTitle("HTTP/3")
        }
    }

    private func get() {
        result = nil; error = nil
        running = model.facade.http3Get(url: url, trust: model.trust) { r, e in
            result = r; error = e; running = nil
        }
    }

    private func cancel() { running?.cancel(); running = nil }
}
