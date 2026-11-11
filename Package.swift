// swift-tools-version:5.9
// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
//
// Kuicksilver for Swift Package Manager (docs/guide/ios.md, "Swift only"): one binary target, the Kuicksilver.xcframework
// attached to the GitHub release of the tag. SwiftPM resolves this file at the tag v<version>; the release commit carries
// the URL and checksum of that version, written by `tools/release/xcframework.sh <version> --write` and checked by
// tools/release/local-release.sh against the xcframework it builds and attaches (docs/release.md, "Every release").
// Between releases, main names the version in preparation, whose zip does not exist yet.
import PackageDescription

let package = Package(
    name: "Kuicksilver",
    platforms: [.iOS(.v15)],  // the Kotlin/Native, OpenSSL and SecTrust floor
    products: [.library(name: "Kuicksilver", targets: ["Kuicksilver"])],
    targets: [
        .binaryTarget(
            name: "Kuicksilver",
            url: "https://github.com/kuicksilver/kuicksilver/releases/download/v0.3.0/Kuicksilver.xcframework.zip",
            checksum: "0000000000000000000000000000000000000000000000000000000000000000"
        ),
    ]
)
