// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Shared
import XCTest

/// The Kotlin facade called from Swift exactly as the app calls it, in the simulator: callbacks arrive on the main
/// thread, which `wait(for:)` keeps running.
final class FacadeSmokeTests: XCTestCase {
    private let facade = SampleFacade()

    override func tearDown() { facade.stopServer() }

    func testEchoAndHttp3AgainstTheInAppServer() throws {
        let started = expectation(description: "server")
        var port: Int32 = -1
        _ = facade.startServer(port: 0, onLog: { print($0) }) { p, e in
            XCTAssertNil(e); port = p?.int32Value ?? -1; started.fulfill()
        }
        wait(for: [started], timeout: 10)
        XCTAssertGreaterThan(port, 0)

        let echoed = expectation(description: "echo")
        _ = facade.quicEcho(host: "::1", port: port, message: "ping", rounds: 3, intervalMs: 0, trust: .sampleCa,
                            followNetwork: true, onLog: { print($0) }) { r, e in
            XCTAssertNil(e); XCTAssertEqual(r?.rounds, 3); echoed.fulfill()
        }
        wait(for: [echoed], timeout: 20)

        let fetched = expectation(description: "h3")
        _ = facade.http3Get(url: "https://127.0.0.1:\(port)/test", trust: .sampleCa) { r, e in
            XCTAssertNil(e); XCTAssertEqual(r?.status, 200)
            XCTAssertTrue(r?.bodyPreview.contains("Hello over HTTP/3") ?? false); fetched.fulfill()
        }
        wait(for: [fetched], timeout: 20)
    }

    func testTheSystemTrustRejectsTheSampleCertificate() throws {
        let started = expectation(description: "server")
        var port: Int32 = -1
        _ = facade.startServer(port: 0, onLog: { _ in }) { p, _ in port = p?.int32Value ?? -1; started.fulfill() }
        wait(for: [started], timeout: 10)
        let failed = expectation(description: "h3")
        _ = facade.http3Get(url: "https://localhost:\(port)/", trust: .platform) { r, e in
            XCTAssertNil(r); XCTAssertNotNil(e); print("expected failure: \(e ?? "")"); failed.fulfill()
        }
        wait(for: [failed], timeout: 20)
    }

    /// A public HTTP/3 site with the system trust store; needs UDP to the internet from the Mac (skipped with
    /// KSL_OFFLINE=1, and skipped when the handshake times out: a proxy or VPN that carries only TCP, such as a
    /// fake-IP DNS proxy answering from 198.18.0.0/15, never lets a QUIC Initial through).
    func testPublicHttp3Site() throws {
        if ProcessInfo.processInfo.environment["KSL_OFFLINE"] == "1" { throw XCTSkip("offline") }
        let fetched = expectation(description: "h3")
        var status: Int32 = 0
        var error: String?
        _ = facade.http3Get(url: "https://cloudflare-quic.com/", trust: .platform) { r, e in
            status = r?.status ?? 0; error = e
            if let r { print("public h3: \(r.status) from \(r.remote), \(r.bodyBytes) bytes, \(r.elapsedMs) ms") }
            fetched.fulfill()
        }
        wait(for: [fetched], timeout: 30)
        if let error, error.contains("Handshake timeout") { throw XCTSkip("no UDP path to the internet: \(error)") }
        XCTAssertEqual(status, 200, error ?? "")
    }
}
