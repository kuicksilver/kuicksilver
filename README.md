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
  <a href="https://github.com/kuicksilver/kuicksilver/actions/workflows/build.yml?query=branch%3Amain"><img alt="Build" src="https://github.com/kuicksilver/kuicksilver/actions/workflows/build.yml/badge.svg?branch=main"></a>
  <a href="https://central.sonatype.com/namespace/io.kuicksilver"><img alt="Maven Central" src="https://img.shields.io/maven-central/v/io.kuicksilver/kuicksilver-quic?label=Maven%20Central"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="gradle/libs.versions.toml"><img alt="Kotlin 2.4" src="https://img.shields.io/badge/Kotlin-2.4-7F52FF?logo=kotlin&logoColor=white"></a>
  <a href="docs/guide/ktor.md"><img alt="Ktor 3.6" src="https://img.shields.io/badge/Ktor-3.6-087CFA"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-JVM%20%7C%20Android%20%7C%20iOS%20%7C%20macOS%20%7C%20Linux%20%7C%20Windows-555">
  <a href="docs/spec/interop.md"><img alt="Interop: msquic, ngtcp2, picoquic, quic-go, quiche, quinn" src="https://img.shields.io/badge/interop-6%20QUIC%20stacks-2EA44F"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/kuicksilver/kuicksilver"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/kuicksilver/kuicksilver/badge"></a>
  <a href="https://www.bestpractices.dev/projects/16654"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/16654/badge"></a>
</p>

Kuicksilver is one QUIC, HTTP/3 and TLS 1.3 implementation in Kotlin for the JVM, Android, iOS, macOS, Linux and
Windows, with drop-in Ktor client and server engines.

> **Status: 0.x, experimental, no production users we know of. Do not use it in production yet.** The API can change between any two 0.x releases
> ([stability](docs/stability.md)). 0.2.0 and 0.2.1 are withdrawn; this README describes 0.3.0,
> the release in preparation. Until 0.3.0 is on Maven Central, build it from `main` and use `0.3.0-SNAPSHOT`
> ([Install](docs/install.md#versions)). Try it, and tell us what breaks.

## Features

Experimental ones (`@ExperimentalKuicksilverApi`) are marked *exp.*

- **HTTP/3, HTTP/2, HTTP/1.1** in one Ktor client engine and one server engine, on the JVM, Android, iOS, macOS, Linux
  and Windows ([Ktor engines](docs/guide/ktor.md)).
- **Alt-Svc discovery, protocol race and adaptive fallback**: HTTP/3 raced against TCP with a head start from the host's
  RTT (TCP almost at once on a network where QUIC was never seen working); a broken alternative or a stalled QUIC
  connection falls back to TCP
  ([discovery](docs/guide/ktor.md#discovery-and-alt-svc), [racing and fallback](docs/guide/ktor.md#racing-and-fallback),
  [stalled connections](docs/guide/ktor.md#stalled-http3-connections)).
- **WebTransport** over HTTP/3, draft-ietf-webtrans-http3-17; servers also take drafts 16, 14 and 02 (browsers),
  clients also offer 16 and 02 (*exp.*, [HTTP/3 guide](docs/guide/http3.md#webtransport-experimental)).
- **QUIC datagrams** (RFC 9221) and HTTP datagrams (RFC 9297) ([QUIC guide](docs/guide/quic.md#datagrams-rfc-9221)).
- **Encrypted Client Hello** (RFC 9849), client and server, over TCP and HTTP/3 (*exp.*,
  [client](docs/guide/ktor.md#encrypted-client-hello-experimental), [server](docs/guide/ktor.md#encrypted-client-hello-on-the-server)).
- **CONNECT-UDP** (RFC 9298, MASQUE): HTTP/3 through a CONNECT-UDP proxy, and the proxy side (*exp.*,
  [client](docs/guide/ktor.md#http3-through-a-connect-udp-proxy-experimental), [proxy](docs/guide/http3.md#connect-udp-experimental)).
- **0-RTT**, opt-in on both sides, replay-guarded (*exp.*, [0-RTT](docs/guide/ktor.md#0-rtt-opt-in-experimental)).
- **Connection migration** across networks (RFC 9000 section 9) (*exp.* in the client,
  [Ktor](docs/guide/ktor.md#connection-migration), [QUIC](docs/guide/quic.md#migration-and-paths)).
- **RFC-strict**: one row per requirement with the tests behind it ([RFC compliance](docs/spec/rfc-compliance.md)); every
  departure for a specific peer is listed ([compatibility shims](docs/spec/compat-shims.md)).
- **Interop** against 6 QUIC stacks: msquic, ngtcp2, picoquic, quic-go, quiche, quinn
  ([interop results](docs/spec/interop.md)).
- **qlog** per connection and per-call diagnostics (which protocol, why, which connection) (*exp.* in the Ktor engines,
  [qlog](docs/guide/quic.md#qlog), [observability](docs/guide/ktor.md#observability-experimental)).

Samples: [`kq`](samples/kq-cli/README.md), a curl-like command line on the client engine (macOS, Linux, Windows);
[realtime-telemetry](samples/realtime-telemetry/README.md) (QUIC streams and datagrams);
[compose-demo](samples/compose-demo/README.md) (HTTP/3 surviving a network switch on Android and iOS).

## Add it

```kotlin
implementation(platform("io.kuicksilver:kuicksilver-bom:0.3.0"))
implementation(platform("io.ktor:ktor-bom:3.6.1"))
implementation("io.kuicksilver:kuicksilver-ktor-client")   // or kuicksilver-ktor-server, kuicksilver-http3, kuicksilver-quic
```

Nothing to install on the system: OpenSSL is built into the library (version pinned in `gradle/openssl.toml`); on Linux,
Kotlin/Native programs use glibc's libresolv and zlib. Android, iOS, Swift-only and Kotlin/Native setups, and the module list: [docs/install.md](docs/install.md).

## Swap the Ktor engine

```kotlin
// client: was HttpClient(OkHttp) or HttpClient(CIO)
val client = HttpClient(Kuicksilver)   // io.kuicksilver.ktor.client.Kuicksilver: HTTP/1.1 or HTTP/2 first, HTTP/3 once the server announces it

// server: was embeddedServer(Netty, port = 8443, module = Application::module)
embeddedServer(Kuicksilver, configure = {   // io.kuicksilver.ktor.server.Kuicksilver
    tlsConnector(TlsIdentity.fromPem(chainPem, keyPem.toCharArray())) { port = 8443 }   // HTTP/1.1 over TLS and HTTP/3, one port
}, module = Application::module).start(wait = true)
```

Your routes, plugins and client calls stay as they are. Discovery modes, trust and pins, HTTP/2, WebSockets and
WebTransport: [Ktor engines](docs/guide/ktor.md). Open both `8443/tcp` and `8443/udp`: [deploying the HTTP/3
server](docs/guide/deployment.md).

## Platforms

| Platform | Targets | Ktor client and server, HTTP/3, QUIC, TLS | How it is tested |
|---|---|---|---|
| JVM 17+ | Linux x86_64 and aarch64 (glibc 2.17+), macOS arm64 and x86_64, Windows x86_64 | yes | every module's suite on macOS arm64 (the x86_64 library is built, not run), on Linux x64 and arm64 (Docker) and on Windows (a Windows 11 VM and GitHub's runners) |
| Android | `minSdk` 24; arm64-v8a, armeabi-v7a, x86_64 | yes | device tests on emulators (API 24 and 35); not on a physical phone in the gate |
| iOS | `iosArm64`, `iosSimulatorArm64` (iOS 15+) | yes | every module's suite on the simulator; **not yet run on a physical device** |
| macOS | `macosArm64` (macOS 12+) | yes | every module's suite on the host |
| Linux | `linuxX64`, `linuxArm64` (Kotlin/Native) | yes | every module's suite in Docker, and the interop image (`linuxArm64`) |
| Windows | `mingwX64` (Kotlin/Native) | yes | test executables on GitHub's Windows runners |

JS and Wasm are not targets. Accelerated UDP, several loops per port and other limits differ by platform:
[stability.md, Platforms](docs/stability.md#platforms).

## Why, and why not

- [Why Kuicksilver, and why not](docs/why-kuicksilver.md): against Cronet, URLSession, OkHttp, Netty QUIC, quiche and
  quic-go, where it is better and where it is worse.
- [How we verify](docs/how-we-verify.md): RFC tables, fuzzing, the release gate on every platform, interop, and the
  numbers we have.
- [Why QUIC](docs/why-quic.md): HTTP/3 against HTTP/1.1 and HTTP/2 under delay, loss and an address change, measured.

## Security model in one line

Host names are always verified and pins are checked on top of the validated chain, never instead of it; 0-RTT is off
unless both sides opt in, and then guarded against replay (ADR-0015); packet keys and TLS secrets stay in native memory; OpenSSL is a pinned, signature-checked release
(version in `gradle/openssl.toml`) built by this repository. The full model is in [docs/spec/threat-model.md](docs/spec/threat-model.md), and
vulnerabilities are reported privately as described in [SECURITY.md](SECURITY.md).

Supply chain: every artifact on Maven Central is signed with the release key (`22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68`),
and `tools/verify/verify-release.sh <version>` checks those signatures, the SBOM and provenance of the GitHub release
(from 0.2.1) and the Swift package's xcframework (from 0.3.0), and rebuilds from the signed tag the native libraries that are reproducible on your host, comparing them
byte for byte with the published ones. What is and is not reproducible yet: [docs/verifying.md](docs/verifying.md).

## Documentation

- [kuicksilver.github.io/kuicksilver](https://kuicksilver.github.io/kuicksilver/): the guide and the API reference
  (Dokka) of every release, from 0.3.0 on.
- Guides: [install](docs/install.md), [TLS](docs/guide/tls.md), [QUIC](docs/guide/quic.md),
  [HTTP/3](docs/guide/http3.md), [Ktor engines](docs/guide/ktor.md), [deploying the HTTP/3 server](docs/guide/deployment.md),
  [iOS](docs/guide/ios.md), [publishing on the App Store](docs/guide/app-store.md), [building from
  source](docs/guide/building.md), the [configuration reference](docs/guide/configuration.md) (every option with its
  default) and [troubleshooting](docs/guide/troubleshooting.md).
- Policies: [API stability and platforms](docs/stability.md), [roadmap](docs/roadmap.md), [verifying a
  release](docs/verifying.md), [how a change is checked](docs/process.md), [OpenSSF Best Practices
  answers](docs/openssf-best-practices.md).
- Evidence: [RFC compliance](docs/spec/rfc-compliance.md) (one row per requirement, details per RFC in
  [docs/spec/rfc/](docs/spec/rfc/)), [interop results](docs/spec/interop.md), [compatibility
  shims](docs/spec/compat-shims.md), [reliability signals](docs/reliability.md), [benchmarks](docs/benchmarks.md),
  [threat model](docs/spec/threat-model.md).
- Internals: [architecture](docs/architecture.md), [decision records](docs/adr/README.md).
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [GOVERNANCE.md](GOVERNANCE.md) (roles, decisions, access continuity).

A note on the name `ksl`: it is this project's C shim between Kotlin and OpenSSL (`kuicksilver-native/src/c/ksl.h`).
It is unrelated to `fuzz/ksl.cc` in ngtcp2, which is a data structure of that project.

## License

Kuicksilver is licensed under the [Apache License 2.0](LICENSE). Its binaries statically link OpenSSL (version pinned in
`gradle/openssl.toml`), which is also Apache-2.0 licensed; see [NOTICE](NOTICE) and [licenses/LICENSE.openssl.txt](licenses/LICENSE.openssl.txt). OpenSSL's
libcrypto contains zlib ([zlib License](licenses/LICENSE.zlib.txt)) and brotli ([MIT](licenses/LICENSE.brotli.txt)) for TLS
certificate compression.
Parts of the Ktor engines and their tests are adapted from Ktor 3.6.0 (Apache-2.0), with per-file attribution.
