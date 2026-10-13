// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Shared
import SwiftUI

/// "Server mode": QUIC on [::]:port serving an HTTP/3 page and the echo protocol, advertised as _kuicksilver._udp.
/// Foreground only: iOS suspends the app, and its sockets, soon after it leaves the screen.
struct ServerView: View {
    @EnvironmentObject private var model: AppModel
    @State private var port = "4433"
    @State private var boundPort: Int32 = -1
    @State private var bonjour = BonjourAdvertiser()
    @State private var bonjourState = "off"
    @State private var log: [String] = []

    var body: some View {
        NavigationStack {
            Form {
                Section("Listener") {
                    TextField("port (0 picks one)", text: $port).keyboardType(.numberPad).disabled(boundPort >= 0)
                    Button(boundPort < 0 ? "Start server" : "Stop server") { boundPort < 0 ? start() : stop() }
                }
                if boundPort >= 0 {
                    Section("Reach it at") {
                        ForEach(LocalAddresses.current(), id: \.self) { a in
                            Text("https://\(a.contains(":") ? "[\(a)]" : a):\(boundPort)/").font(.caption.monospaced()).textSelection(.enabled)
                        }
                        LabeledContent("Bonjour", value: bonjourState)
                        Text("Clients trust it with the Sample CA (or trust on first use). Echo: the QUIC echo tab of another phone.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                Section("Log") {
                    ForEach(Array(log.enumerated()), id: \.offset) { _, line in Text(line).font(.caption.monospaced()) }
                }
            }
            .navigationTitle("Server mode")
        }
    }

    private func start() {
        log = []
        model.facade.startServer(port: Int32(port) ?? 4433, onLog: { append($0) }) { p, e in
            if let p {
                boundPort = p.int32Value
                let err = bonjour.start(name: "Kuicksilver on \(UIDevice.current.name)", port: UInt16(truncatingIfNeeded: boundPort))
                bonjourState = err == 0 ? "_kuicksilver._udp" : "error \(err)"
            }
            if let e { append("error: \(e)") }
        }
    }

    private func stop() {
        bonjour.stop(); bonjourState = "off"
        model.facade.stopServer(); boundPort = -1; append("stopped")
    }

    private func append(_ line: String) { log.append(line); if log.count > 500 { log.removeFirst(log.count - 500) } }
}
