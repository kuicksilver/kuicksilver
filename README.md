<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Kuicksilver

**Status: 0.x, experimental.** The API can change between any two 0.x releases, nothing is published to Maven Central
yet, and the CI described below runs on the maintainers' machines until the repository's first public build. Do not
use it in production yet; do try it, and tell us what breaks.

Kuicksilver is a Kotlin Multiplatform network stack: QUIC v1 and v2 (RFC 9000/9001/9002/9369, datagrams of RFC 9221,
path MTU discovery of RFC 8899), HTTP/3 with QPACK (RFC 9114/9204, priorities of RFC 9218, Extended CONNECT and
WebSockets of RFC 9220, HTTP datagrams of RFC 9297), TLS 1.3 over TCP, and Ktor 3.6 client and server engines on top
of them. The protocol logic is Kotlin; cryptography and certificate handling come from OpenSSL 3.5, statically linked
behind one small C shim, `ksl`. The QUIC core is sans-IO, so the same code runs on the JVM, Android and Kotlin/Native
and in a deterministic network simulator.

```kotlin
val client = HttpClient(Kuicksilver)          // HTTP/1.1 first, HTTP/3 once the server announces it
embeddedServer(Kuicksilver) { /* ... */ }      // HTTP/1.1 over TLS and HTTP/3 on one port
```

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
| JVM 17+ | Linux x86_64 / aarch64, macOS arm64 / x86_64, Windows x86_64 | yes | yes | Linux: glibc 2.17 or newer (the native library is built in manylinux2014); musl (Alpine) is not supported in v1. macOS 11 or newer. Accelerated UDP everywhere: on Linux (GSO/GRO, ECN, DF), macOS (ECN, DF; no GSO/GRO) and Windows (USO/URO and ECN where the Windows version grants them, DF). `loops > 1` needs Linux. The Windows JNI library is cross-built with mingw-w64; on Windows the JVM suites have no passing CI run yet (GitHub Actions is paused) and their verification in a local Windows VM is pending. |
| Android | `minSdk` 24; arm64-v8a, armeabi-v7a, x86_64 | yes | yes | Native libraries are aligned for 16 KiB pages; accelerated UDP as on Linux. |
| Kotlin/Native Linux | `linuxX64`, `linuxArm64` | yes | yes | glibc of the Kotlin/Native sysroot (2.19 on x64, 2.25 on arm64). |
| Kotlin/Native Apple | `macosArm64`, `iosArm64`, `iosSimulatorArm64` (no `macosX64`: deprecated by Kotlin; the JVM on Intel Macs is served by the JNI library) | yes | yes | The server runs on the accelerated `ksl` socket (ADR-0006): ECN and DF, no GSO/GRO (Darwin has none), `loops = 1` only (Darwin has no `SO_REUSEPORT` flow hashing). The test suites of every module run on the iOS simulator (`iosSimulatorArm64Test`), and `:kuicksilver-ktor-client:iosHostInteropTest` runs the simulator against a peer on the host (Ktor HTTP/3 and HTTP/1.1, raw QUIC in both directions, IPv4 and IPv6); network following through `NWPathMonitor` (`followDefaultNetwork`) is in `appleMain`. Not yet verified on a physical device. |
| Kotlin/Native Windows | `mingwX64` | yes | yes | The server runs on the accelerated Winsock socket (`WSASendMsg`/`WSARecvMsg`; ECN on Windows 10 2004+ / Server 2022, USO/URO where granted), `loops = 1` only (exclusive bind, no `SO_REUSEPORT`). A `0.0.0.0` bind is IPv4-only there (bind `::` for both families). `TrustConfig.Platform` is not available yet: use `AnchoredCa` (optionally under `Pinned`). Cross-built on macOS/Linux; no passing CI run on Windows yet (GitHub Actions is paused), verification in a local Windows VM is pending. |

TLS over TCP (`TlsConnection`, `Socket.tls()`) works on every target above. JS and Wasm are not targets.

Not in v1, by decision: HTTP/2 (ADR-0009), HTTP/3 server push, WebTransport, multipath, OpenSSL 4.x. 0-RTT
is available as an opt-in, experimental API and is off by default (ADR-0015).

## Quick start

Artifacts are not on Maven Central yet. Until they are, build from source (see [CONTRIBUTING.md](CONTRIBUTING.md))
and consume the modules through a Gradle composite build, as
[`samples/realtime-telemetry`](samples/realtime-telemetry/README.md) does:

```kotlin
// settings.gradle.kts of your project
includeBuild("../kuicksilver")

// build.gradle.kts
dependencies {
    implementation("io.kuicksilver:kuicksilver-ktor-client:0.1.0-SNAPSHOT")
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

## Security model in one line

Host names are always verified and pins are checked on top of the validated chain, never instead of it; 0-RTT is off
unless both sides opt in, and then guarded against replay (ADR-0015); packet keys and TLS secrets stay in native memory; OpenSSL is a pinned, signature-checked 3.5 LTS release
built by this repository. The full model is in [docs/spec/threat-model.md](docs/spec/threat-model.md), and
vulnerabilities are reported privately as described in [SECURITY.md](SECURITY.md).

## Interoperability

The QUIC Interop Runner (pinned in `tools/interop/runner.lock`) is run against msquic, ngtcp2, picoquic, quic-go,
quiche and quinn, with Kuicksilver as server and as client, from two images: the JVM build and a Kotlin/Native
`linuxArm64` build. Latest local results (2026-10-08):

| Image | Cases | Green cells |
|---|---|---|
| JVM | 18 cases (handshake, transfer, longrtt, chacha20, multiplexing, retry, keyupdate, blackhole, ecn, amplificationlimit, handshakeloss, transferloss, handshakecorruption, transfercorruption, ipv6, v2, rebind-port, rebind-addr) x 6 peers x 2 roles | 188 / 216 |
| Kotlin/Native `linuxArm64` | handshake, transfer, retry, keyupdate, ecn, rebind-port x 5 peers x 2 roles | 54 / 60 |
| both | `http3` | green in both roles against every peer that implements the case (ngtcp2, picoquic, quic-go, quiche, quinn) |

Every red cell is analysed, cell by cell, in the interop section of
[docs/spec/rfc-compliance.md](docs/spec/rfc-compliance.md); `tools/interop/required.json` lists the cells that must
stay green. RFC coverage, section by section, with the tests behind each row, is in the same document.

## Documentation

- [docs/architecture.md](docs/architecture.md) — how the code is organised, invariants, entry points.
- [docs/roadmap.md](docs/roadmap.md) — what 0.1.0 ships, its stated limits, and what 0.2.0 and later bring.
- [docs/guide/](docs/guide/quic.md) — user guides: [TLS](docs/guide/tls.md), [QUIC](docs/guide/quic.md),
  [HTTP/3](docs/guide/http3.md), [Ktor engines](docs/guide/ktor.md).
- [docs/spec/rfc-compliance.md](docs/spec/rfc-compliance.md) — RFC coverage and the interop matrix.
- [docs/spec/threat-model.md](docs/spec/threat-model.md) — threat model and the `negative_*` security controls.
- [docs/adr/](docs/adr/README.md) — architecture decision records.
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

A note on the name `ksl`: it is this project's C shim between Kotlin and OpenSSL (`kuicksilver-native/src/c/ksl.h`).
It is unrelated to `fuzz/ksl.cc` in ngtcp2, which is a data structure of that project.

## License

Kuicksilver is licensed under the [Apache License 2.0](LICENSE). Its binaries statically link OpenSSL 3.5, which is
also Apache-2.0 licensed; see [NOTICE](NOTICE) and [licenses/LICENSE.openssl.txt](licenses/LICENSE.openssl.txt).
Parts of the Ktor engines and their tests are adapted from Ktor 3.6.0 (Apache-2.0), with per-file attribution.
