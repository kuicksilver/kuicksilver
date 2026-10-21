<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

<p align="center">
  <img src="docs/assets/kuicksilver.jpg" width="640" alt="Kuicksilver">
</p>

<h1 align="center">Kuicksilver</h1>

<p align="center">
  <b>QUIC and HTTP/3 for Kotlin Multiplatform</b>, written in Kotlin, with Ktor client and server engines.
</p>

<p align="center">
  <a href="https://central.sonatype.com/namespace/io.kuicksilver"><img alt="Maven Central" src="https://img.shields.io/maven-central/v/io.kuicksilver/kuicksilver-quic?label=Maven%20Central"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="gradle/libs.versions.toml"><img alt="Kotlin 2.4" src="https://img.shields.io/badge/Kotlin-2.4-7F52FF?logo=kotlin&logoColor=white"></a>
  <a href="docs/guide/ktor.md"><img alt="Ktor 3.6" src="https://img.shields.io/badge/Ktor-3.6-087CFA"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-JVM%20%7C%20Android%20%7C%20iOS%20%7C%20macOS%20%7C%20Linux%20%7C%20Windows-555">
  <a href="docs/spec/rfc-compliance.md"><img alt="Interop: msquic, ngtcp2, picoquic, quic-go, quiche, quinn" src="https://img.shields.io/badge/interop-6%20QUIC%20stacks-2EA44F"></a>
</p>

> **Status: 0.x, experimental.** The API can change between any two 0.x releases, and 0.2.0 is on Maven Central. Do
> not use it in production yet; do try it, and tell us what breaks. [docs/stability.md](docs/stability.md) says which
> API is stable and which is experimental.

```kotlin
val client = HttpClient(Kuicksilver)          // HTTP/1.1 first, HTTP/3 once the server announces it
embeddedServer(Kuicksilver) { /* ... */ }      // HTTP/1.1 over TLS and HTTP/3 on one port
```

## Why Kuicksilver

- **One implementation, every Kotlin platform.** QUIC, HTTP/3 and QPACK are Kotlin code, not bindings to a different
  library per platform: the same sans-IO core runs on the JVM, Android, iOS, macOS, Linux and Windows, and in a
  deterministic network simulator for tests.
- **Drop-in Ktor engines.** `HttpClient(Kuicksilver)` discovers HTTP/3 through `Alt-Svc` and falls back to HTTP/1.1;
  `embeddedServer(Kuicksilver)` serves HTTP/1.1 over TLS and HTTP/3 on one port.
- **Connections that survive network changes.** QUIC connection migration, and `followDefaultNetwork` on Android and
  Apple moves a connection when the phone switches from Wi-Fi to cellular.
- **The rest of modern QUIC.** Datagrams (RFC 9221), path MTU discovery, QUIC v2, stream priorities, WebSockets and
  Extended CONNECT over HTTP/3, qlog; 0-RTT and BBR as opt-in, experimental features.
- **Tested against the others.** The QUIC Interop Runner against msquic, ngtcp2, picoquic, quic-go, quiche and quinn,
  in both roles, and a [published benchmark table](docs/benchmarks.md) against quiche, quinn and msquic.
- **No system OpenSSL.** Cryptography and certificates come from OpenSSL 3.5, pinned, signature-checked, built by this
  repository and statically linked behind one small C shim, `ksl`.

In protocol terms: QUIC v1 and v2 (RFC 9000/9001/9002/9369, datagrams of RFC 9221, path MTU discovery of RFC 8899),
HTTP/3 with QPACK (RFC 9114/9204, priorities of RFC 9218, Extended CONNECT and WebSockets of RFC 9220, HTTP datagrams
of RFC 9297), TLS 1.3 over TCP, and Ktor 3.6 client and server engines on top of them.

## Quick start

Artifacts are on Maven Central:

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.kuicksilver:kuicksilver-ktor-client:0.2.0")
}
```

The snippets below are taken from the guides, which say what every option does.

### Ktor client

```kotlin
val client = HttpClient(Kuicksilver) {
    engine {
        trust = TrustConfig.Pinned(
            setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
            base = TrustConfig.Platform,
        )
        http3 { discovery = Http3DiscoveryMode.Auto }   // the default: HTTP/1.1 first, HTTP/3 after Alt-Svc
    }
    install(HttpTimeout) { connectTimeoutMillis = 5_000; socketTimeoutMillis = 15_000 }
}
```

`Preferred` tries HTTP/3 first and falls back to HTTP/1.1, `H3Only` never uses TCP, `H1Only` never uses QUIC. The
fallback keeps the same trust and pins. Details: [docs/guide/ktor.md](docs/guide/ktor.md).

**Supported Ktor: 3.6.x.** The engines use a few Ktor internals, so they check the Ktor version when a client engine is
created or a server engine starts (JVM and Android) and fail with a clear message on another major.minor;
`-Dkuicksilver.ktor.versionCheck=false` skips the check. On Kotlin/Native a mismatch fails at link time. New Ktor minors
are adopted in Kuicksilver releases; see [Supported Ktor versions](docs/guide/ktor.md#supported-ktor-versions).

### Ktor server

```kotlin
embeddedServer(Kuicksilver, configure = {
    tlsConnector(TlsIdentity.fromPem(chainPem, keyPem.toCharArray())) {   // the key array is zeroed after import
        port = 443
    }
}) {
    routing {
        get("/") { call.respondText("hello over ${call.request.httpVersion}") }
    }
}.start(wait = true)
```

A TLS connector serves HTTP/1.1 over TLS on TCP and HTTP/3 on UDP on the same port number, and advertises HTTP/3
with `Alt-Svc`.

### Raw QUIC

```kotlin
// server
val server = QuicEndpoint.bind(
    InetSocketAddress("0.0.0.0", 4433),
    quicEndpointConfig { this.server = quicServerConfig(tlsServerConfig) { this.quic = quic } },
)
val incoming = server.accept()
val echoed = incoming.acceptStream()
echoed.output.writeStringUtf8(echoed.input.readUTF8Line() ?: "")
echoed.output.flushAndClose()

// client
val client = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))
val connection = client.connect(serverAddress, quicClientConfig(tlsClientConfig) { this.quic = quic })
val stream = connection.openBidi()
stream.output.writeStringUtf8("ping\n")
stream.output.flushAndClose()
val reply = stream.input.readUTF8Line()
connection.close(code = 0, reason = "done")
```

`quic` is a `quicConfig { }`, `tlsServerConfig` / `tlsClientConfig` are `tlsConfig(TlsRole.Server / Client) { }`
with ALPN set. Datagrams, stream priorities, connection migration and the sans-IO core are in
[docs/guide/quic.md](docs/guide/quic.md); HTTP/3 without Ktor is in [docs/guide/http3.md](docs/guide/http3.md).

## Modules

| Artifact (`io.kuicksilver:`) | What it is | Guide |
|---|---|---|
| `kuicksilver-native` | the `ksl` C shim with OpenSSL 3.5 inside, its JNI and cinterop bindings, the native loader | [architecture](docs/architecture.md) |
| `kuicksilver-tls` | TLS 1.3 configuration, trust (platform, private CA, SPKI pins, TOFU), TLS over any byte channel | [tls.md](docs/guide/tls.md) |
| `kuicksilver-ktor-network` | `Socket.tls()` / `Socket.tlsServer()` for ktor-network sockets | [tls.md](docs/guide/tls.md) |
| `kuicksilver-quic` | QUIC transport: streams, datagrams, migration, coroutine API and sans-IO core | [quic.md](docs/guide/quic.md) |
| `kuicksilver-http3` | HTTP/3 and QPACK over `kuicksilver-quic` | [http3.md](docs/guide/http3.md) |
| `kuicksilver-ktor-client` | `HttpClient(Kuicksilver)`: HTTP/1.1 over TLS and HTTP/3, Alt-Svc discovery, racing, fallback | [ktor.md](docs/guide/ktor.md) |
| `kuicksilver-ktor-server` | `embeddedServer(Kuicksilver)`: HTTP/1.1 over TLS on TCP and HTTP/3 on UDP, same port | [ktor.md](docs/guide/ktor.md) |

Each module depends only on the layer directly below it (ADR-0005). `kuicksilver-testing` (network simulator and
in-memory UDP), `kuicksilver-bench` and `kuicksilver-interop` live in this repository but are not published.

## Platforms

| Platform | Targets | QUIC client | QUIC server | Limits |
|---|---|---|---|---|
| JVM 17+ | Linux x86_64 / aarch64, macOS arm64 / x86_64, Windows x86_64 | yes | yes | Linux: glibc 2.17 or newer (the native library is built in manylinux2014); musl (Alpine) is not supported. macOS 11 or newer. Accelerated UDP everywhere: on Linux (GSO/GRO, ECN, DF), macOS (ECN, DF; no GSO/GRO) and Windows (USO/URO and ECN where the Windows version grants them, DF). `loops > 1` needs Linux. The Windows JNI library is cross-built with mingw-w64; the JVM suites on Windows were verified in a local Windows 11 VM (Parallels); the GitHub Actions workflows are disabled, and the gate runs locally (`tools/ci/local-matrix.sh --with-windows`, see [Platforms](docs/stability.md#platforms)). |
| Android | `minSdk` 24; arm64-v8a, armeabi-v7a, x86_64 | yes | yes | Native libraries are aligned for 16 KiB pages; accelerated UDP as on Linux. |
| Kotlin/Native Linux | `linuxX64`, `linuxArm64` | yes | yes | glibc of the Kotlin/Native sysroot (2.19 on x64, 2.25 on arm64). |
| Kotlin/Native Apple | `macosArm64`, `iosArm64`, `iosSimulatorArm64` (no `macosX64`: deprecated by Kotlin; the JVM on Intel Macs is served by the JNI library) | yes | yes | macOS 12 or newer, iOS 15 or newer. The server runs on the accelerated `ksl` socket (ADR-0006): ECN and DF, no GSO/GRO (Darwin has none), `loops = 1` only (Darwin has no `SO_REUSEPORT` flow hashing). The test suites of every module run on the iOS simulator (`iosSimulatorArm64Test`), and `:kuicksilver-ktor-client:iosHostInteropTest` runs the simulator against a peer on the host (Ktor HTTP/3 and HTTP/1.1, raw QUIC in both directions, IPv4 and IPv6); network following through `NWPathMonitor` (`followDefaultNetwork`) is in `appleMain`. Not yet verified on a physical device. |
| Kotlin/Native Windows | `mingwX64` | yes | yes | The server runs on the accelerated Winsock socket (`WSASendMsg`/`WSARecvMsg`; ECN where Windows accepts `IP_ECN`, probed when the socket opens and verified on Windows 11, USO/URO where granted), `loops = 1` only (exclusive bind, no `SO_REUSEPORT`). A `0.0.0.0` bind opens a dual-stack socket, as on Linux and Apple. `TrustConfig.Platform` verifies with CryptoAPI (the Windows root store, AIA, soft-fail revocation of the leaf). Cross-built on macOS/Linux and verified in a local Windows 11 VM (Parallels); the GitHub Actions workflows are disabled, and the gate runs locally (`tools/ci/local-matrix.sh`). |

TLS over TCP (`TlsConnection`, `Socket.tls()`) works on every target above. JS and Wasm are not targets.

Not in 0.2.x: HTTP/2 (ADR-0009, by decision), HTTP/3 server push, WebTransport (planned for 0.3.0, experimental), multipath
(later, see the [roadmap](docs/roadmap.md)), OpenSSL 4.x. 0-RTT
is available as an opt-in, experimental API and is off by default (ADR-0015).

## Security model in one line

Host names are always verified and pins are checked on top of the validated chain, never instead of it; 0-RTT is off
unless both sides opt in, and then guarded against replay (ADR-0015); packet keys and TLS secrets stay in native memory; OpenSSL is a pinned, signature-checked 3.5 LTS release
built by this repository. The full model is in [docs/spec/threat-model.md](docs/spec/threat-model.md), and
vulnerabilities are reported privately as described in [SECURITY.md](SECURITY.md).

Supply chain: every artifact on Maven Central is signed with the release key (`22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68`),
and `tools/verify/verify-release.sh <version>` checks those signatures, the SBOM and provenance of the GitHub release
(from 0.2.1), and rebuilds from the signed tag the native libraries that are reproducible on your host, comparing them
byte for byte with the published ones. What is and is not reproducible yet: [docs/verifying.md](docs/verifying.md).

## Interoperability

The QUIC Interop Runner (pinned in `tools/interop/runner.lock`) is run against msquic, ngtcp2, picoquic, quic-go,
quiche and quinn, with Kuicksilver as server and as client, from two images: the JVM build and a Kotlin/Native
`linuxArm64` build. Latest local results (2026-10-13, runner 740c05a, the 0.2.0 code):

| Image | Cases | Green cells |
|---|---|---|
| JVM | 21 cases (the 18 of 0.1.0 — handshake, transfer, longrtt, chacha20, multiplexing, retry, keyupdate, blackhole, ecn, amplificationlimit, handshakeloss, transferloss, handshakecorruption, transfercorruption, ipv6, v2, rebind-port, rebind-addr — plus http3, resumption, zerortt) x 6 peers x 2 roles | 227 of the 237 cells both sides support |
| Kotlin/Native `linuxArm64` | handshake, transfer, retry, keyupdate, ecn, rebind-port, http3, resumption, zerortt x 6 peers x 2 roles | 96 of the 99 cells both sides support |
| both | `resumption`, `zerortt` | green in both roles against all six peers |

Every red cell is analysed, cell by cell, in the interop section of
[docs/spec/rfc-compliance.md](docs/spec/rfc-compliance.md); `tools/interop/required.json` lists the cells that must
stay green. RFC coverage, section by section, with the tests behind each row, is in the same document.

## Documentation

- [docs/architecture.md](docs/architecture.md) — how the code is organised, invariants, entry points.
- [docs/roadmap.md](docs/roadmap.md) — the never-published 0.1.0 candidate, what 0.2.0 ships, its stated limits, and what later releases bring.
- [docs/guide/](docs/guide/quic.md) — user guides: [TLS](docs/guide/tls.md), [QUIC](docs/guide/quic.md),
  [HTTP/3](docs/guide/http3.md), [Ktor engines](docs/guide/ktor.md), [iOS](docs/guide/ios.md),
  [publishing on the App Store](docs/guide/app-store.md), the [configuration reference](docs/guide/configuration.md)
  (every option with its default) and [troubleshooting](docs/guide/troubleshooting.md).
- [docs/stability.md](docs/stability.md) — what 0.2.x promises: stable and experimental API, the ABI checks, the `ksl`
  ABI, the Ktor and OpenSSL version policies, supported platforms.
- [docs/spec/rfc-compliance.md](docs/spec/rfc-compliance.md) — RFC coverage and the interop matrix.
- [docs/benchmarks.md](docs/benchmarks.md) — goodput, CPU per GB and handshakes per second against quiche, quinn and
  msquic, with the method and its caveats (one Apple Silicon host; the amd64 peer images run emulated).
- [docs/spec/threat-model.md](docs/spec/threat-model.md) — threat model and the `negative_*` security controls.
- [docs/verifying.md](docs/verifying.md) — verifying a release: signatures, Gradle dependency verification, SBOM and
  provenance, rebuilding the native libraries.
- [docs/adr/](docs/adr/README.md) — architecture decision records.
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

A note on the name `ksl`: it is this project's C shim between Kotlin and OpenSSL (`kuicksilver-native/src/c/ksl.h`).
It is unrelated to `fuzz/ksl.cc` in ngtcp2, which is a data structure of that project.

## License

Kuicksilver is licensed under the [Apache License 2.0](LICENSE). Its binaries statically link OpenSSL 3.5, which is
also Apache-2.0 licensed; see [NOTICE](NOTICE) and [licenses/LICENSE.openssl.txt](licenses/LICENSE.openssl.txt).
Parts of the Ktor engines and their tests are adapted from Ktor 3.6.0 (Apache-2.0), with per-file attribution.
