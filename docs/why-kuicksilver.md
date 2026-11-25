<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Why Kuicksilver, and why not

Why not Cronet, URLSession, OkHttp, Netty QUIC, quiche or quic-go? This page compares them with Kuicksilver, both where
Kuicksilver is better and where it is worse. Every statement about another project links to that project's own
documentation or code, as read on 2026-11-19. Where we found no source for a feature of another project, the table says
"not checked". That means we make no claim, not that the feature is missing. Corrections with a source are welcome as
issues.

**The short version.** Kuicksilver is young: 0.x, experimental API, no production users we know of, one maintainer
([GOVERNANCE.md](../GOVERNANCE.md)). The libraries below carry real traffic for large services. Choose Kuicksilver if
you need one QUIC and HTTP/3 stack, with Ktor engines, across JVM, Android, iOS, macOS, Linux and Windows from one
Kotlin codebase, and you can live with a pre-1.0 library. If you need one platform only and a long production record,
the platform's own stack or one of the mature libraries below is the safer choice today.

## Platform reach

| | JVM | Android | iOS | macOS (native) | Linux (native) | Windows (native) | Language, API |
|---|---|---|---|---|---|---|---|
| **Kuicksilver** | yes | yes | yes | yes | yes | yes | Kotlin; Ktor engines, coroutine API ([platforms](stability.md#platforms)) |
| **Cronet** | no: "a library for use on Android" ([Cronet README][cronet-readme]) | yes ([Android docs][cronet-android]) | dropped its best-effort iOS build in M108 ([Cronet README][cronet-readme]) | no: "a library for use on Android" ([Cronet README][cronet-readme]) | no: "a library for use on Android" ([Cronet README][cronet-readme]) | no: "a library for use on Android" ([Cronet README][cronet-readme]) | Chromium's network stack as a library ([Android docs][cronet-android]) |
| **URLSession** | no | no (Apple's URLSession) | yes, HTTP/3 from iOS 15 ([TN3102][tn3102]) | yes, HTTP/3 from macOS 12 ([WWDC21 10094][wwdc-h3]) | not Apple's; swift-corelibs-foundation's FoundationNetworking has a URLSession over libcurl for non-Apple platforms ([swift-corelibs-foundation][scf]); HTTP/3 there not checked | not Apple's; swift-corelibs-foundation's FoundationNetworking has a URLSession over libcurl for non-Apple platforms ([swift-corelibs-foundation][scf]); HTTP/3 there not checked | Apple's system networking API ([URLSession][urlsession]) |
| **OkHttp** | Java 8+ ([README][okhttp-readme]) | Android 5.0+ ([README][okhttp-readme]) | no: JVM and Android artifacts only ([README][okhttp-readme]) | (JVM only) | (JVM only) | (JVM only) | Kotlin, JVM and Android artifacts ([README][okhttp-readme]) |
| **Netty QUIC** | yes, with native libraries for Linux x86_64 and aarch64, macOS x86_64 and aarch64, Windows x86_64 ([build profiles][netty-quic-pom]) | build profiles for four Android ABIs (AAR, minSdk 21) ([build profiles][netty-quic-pom]); no Android artifact on Maven Central ([4.2.21.Final files][netty-quic-central]) | no: no iOS build profile ([build profiles][netty-quic-pom]) | (JVM only) | (JVM only) | (JVM only) | Java, Netty channels; QUIC through quiche and BoringSSL over JNI ([build profiles][netty-quic-pom]) |
| **quiche** | no binding of its own; used from the JVM through Netty QUIC (JNI) | builds with the NDK, API 21+ ([README][quiche-readme]) | builds with Xcode ([README][quiche-readme]) | yes, tested in CI ([stable.yml][quiche-ci]) | yes, tested in CI ([stable.yml][quiche-ci]) | builds with NASM on Windows ([README][quiche-readme]) | Rust, with an optional C API ([README][quiche-readme]) |
| **quic-go** | no | not covered by its CI ([cross-compile.sh][quic-go-xc]) | not covered by its CI ([cross-compile.sh][quic-go-xc]) | yes, unit tests in CI on all three ([unit.yml][quic-go-ci]) | yes, unit tests in CI on all three ([unit.yml][quic-go-ci]) | yes, unit tests in CI on all three ([unit.yml][quic-go-ci]) | Go ([README][quic-go-readme]) |

Where Kuicksilver is better: one implementation, the same QUIC and HTTP/3 code, on every Kotlin target, including
Kotlin/Native on iOS, macOS, Linux and Windows, behind the same Ktor API on client and server. A Kotlin Multiplatform
app gets HTTP/3 in `commonMain` without a different library per platform.

Where it is worse: it covers Kotlin only. On a single platform the native stacks are closer to the system: URLSession
ships with the OS and adds nothing to the app; Cronet is Chromium's own network stack ([Android docs][cronet-android]).

## Protocol features

| | HTTP/3 | WebTransport | CONNECT-UDP (RFC 9298) | ECH (RFC 9849) | 0-RTT | Connection migration |
|---|---|---|---|---|---|---|
| **Kuicksilver** | yes, client and server ([RFC 9114](spec/rfc-compliance.md#http)) | yes, experimental, client and server: draft-16 on the wire, with draft-02 and draft-14 codepoints accepted for browsers; tested with Chrome and Firefox over draft-02 ([details](spec/rfc/draft-ietf-webtrans-http3.md#webtransport)) | planned for 0.3.0 ([roadmap](roadmap.md#feature-parity-decided-2026-11-16)) | yes, experimental, from 0.3.0, client and server (shared mode) over QUIC and TCP, GREASE on by default, on OpenSSL 4.1 ([RFC 9849 row](spec/rfc/9849.md#ech), [ADR-0019](adr/0019-openssl-4-and-ech.md)) | yes, opt-in and experimental, with replay protection ([RFC 9001 §4.6](spec/rfc/9001.md#s4-6-0-rtt), ADR-0015) | yes: passive and active, preferred address, and following Android's and Apple's default network in the Ktor client ([RFC 9000 §9](spec/rfc/9000.md#s9-client-initiated-active-migration)) |
| **Cronet** | yes ([Android docs][cronet-android]) | not checked | not checked | not checked | not checked | yes, says Google's Cronet transport for OkHttp ([cronet-transport-for-okhttp][cronet-okhttp]) |
| **URLSession** | yes, on by default from iOS 15 and macOS 12, found through HTTPS records or Alt-Svc ([TN3102][tn3102], [WWDC21 10094][wwdc-h3]) | not checked | not checked | not checked | not checked | not checked |
| **OkHttp** | no: "HTTP/3 is not natively supported by OkHttp" ([Protocol.kt][okhttp-protocol]); Google's Cronet transport adds it by replacing OkHttp's core, so OkHttp's caching, retries, authentication and network interceptors are bypassed and WebSockets are not supported ([cronet-transport-for-okhttp][cronet-okhttp]) | not checked | not checked | not checked | not checked | through the Cronet transport ([cronet-transport-for-okhttp][cronet-okhttp]) |
| **Netty QUIC** | yes, `netty-codec-http3`, part of Netty 4.2 (4.2.21.Final) ([Maven Central][netty-http3]) | not checked | not checked | not checked | yes, `QuicSslContextBuilder.earlyData(true)` ([QuicSslContextBuilder][netty-quic-ssl]) | the server follows a client's migration (`QuicPathEvent.PeerMigrated`); no client migration API found ([QuicPathEvent][netty-quic-path]) |
| **quiche** | yes ([README][quiche-readme]) | not checked | not checked | not checked | yes, `enable_early_data`, `is_in_early_data` ([lib.rs][quiche-lib]) | yes, `probe_path`, `migrate` ([lib.rs][quiche-lib]) |
| **quic-go** | yes ([README][quic-go-readme]) | yes, in the separate webtransport-go ([README][quic-go-readme]) | yes, in the separate masque-go ([README][quic-go-readme]) | through Go's crypto/tls (`EncryptedClientHelloConfigList`); "no changes to quic-go will be needed" ([issue #3905][quic-go-ech]) | yes, `DialEarly` ([client docs][quic-go-0rtt]) | client-initiated migration and NAT rebinding; the preferred address is future work ([docs][quic-go-mig]) |

Where Kuicksilver is better: for a Kotlin app, the list comes in one library behind one Ktor API (quic-go has a
comparable list for Go, with WebTransport and CONNECT-UDP in companion libraries): HTTP/3, WebTransport, 0-RTT,
migration, QUIC datagrams (RFC 9221), path MTU discovery, QUIC v2, priorities, WebSockets over HTTP/3 and HTTP/2,
HTTP/2, qlog, PROXY protocol on the server. Per requirement, with the tests behind each row:
[rfc-compliance.md](spec/rfc-compliance.md). On a phone, the Ktor client can move a running HTTP/3 download from Wi-Fi
to cellular (`followDefaultNetwork`); the [Compose Multiplatform demo](../samples/compose-demo/README.md) shows it next
to OkHttp and CIO.

Where it is worse: CONNECT-UDP and ECH are not in a release yet; quic-go's companion library masque-go has CONNECT-UDP today. Multipath QUIC is
planned for 0.4.0 ([roadmap](roadmap.md#040-planned)). WebTransport follows a draft and is
experimental. Safari has not been tested against it ([interop](spec/interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23)).

## Performance

What has been measured is in [benchmarks.md](benchmarks.md) and [why-quic.md](why-quic.md), with their methods and
caveats. In short (one Apple Silicon host; the quiche and msquic interop images ran under amd64 emulation):

| Measurement | Kuicksilver | Peers | Source, date |
|---|---|---|---|
| Server CPU per GB, 1 GiB download | JVM 2.72 s, Native 3.47 s | msquic 1.86 s (emulated); quiche 11.47 s (emulated); quinn 15.56 s | [benchmarks.md, CPU per GB](benchmarks.md#cpu-per-gb), 2026-10-21 |
| Handshakes per second, one server | JVM 1750, Native 1524 | quinn 3452; msquic 3543 (emulated); quiche 228 (emulated) | [benchmarks.md, Handshakes per second](benchmarks.md#handshakes-per-second), 2026-10-21 |
| Server CPU per handshake | JVM 0.95 ms, Native 0.79 ms | quinn 0.53 ms; msquic 0.70 ms (emulated) | same |
| Time to first byte, new connection, 100 ms RTT | HTTP/3 225 ms; with 0-RTT 114 ms; HTTP/2 321 ms | OkHttp HTTP/2 469 ms | [why-quic.md, Connection setup](why-quic.md#connection-setup), 2026-11-09 |
| 10 MiB download at 100 ms RTT, 3 % loss (median) | HTTP/3 96.7 s | OkHttp HTTP/2 125.9 s, HTTP/1.1 129.3 s | [why-quic.md, Downloads](why-quic.md#downloads-under-delay-and-loss), 2026-11-09 |

All peer numbers are of the peers' interop endpoints, not their tuned servers, so they flatter no one: quinn and msquic
handshake at twice Kuicksilver's rate and msquic uses less CPU per GB even under emulation, while quinn and quiche use
more CPU per GB. The handshake gap is on the
[roadmap](roadmap.md#030--client-and-server-completeness-feature-parity-planned).

- Planned for 0.4.0 ([roadmap](roadmap.md#040-planned)): HTTP/3 client benchmarks against Cronet and URLSession on a
  phone (requests per second, time to first byte, CPU and battery). No tool in the repository measures these yet.
- TODO(measure): the handshake table again after the 0.3.0 changes (`SSL_CTX` shared per server configuration):
  `tools/bench/run-table.sh --phases handshakes`.
- Planned for 0.4.0 ([roadmap](roadmap.md#040-planned)): against Netty's HTTP/3 server on the JVM (goodput, CPU per
  GB). The engine interop bench (`kuicksilver-engine-interop`) checks correctness against it, not speed.

## Binary size

What Kuicksilver adds to an app:

| Where | Size | Source, date |
|---|---|---|
| iOS app, Release arm64, linked bytes (OpenSSL 1.98 MB, `ksl` 0.03 MB, Kotlin of Kuicksilver 1.43 MB, plus the Kotlin runtime, stdlib, coroutines and ktor-io a Kotlin app may already have) | 5.60 MB in all; about 3.4 MB for an app that already ships Kotlin | [ios.md, Size](guide/ios.md#size), 2026-10-14, 0.2.0 code (`tools/check/ios-size.sh`) |
| `kuicksilver-native` Android AAR, three ABIs | about 3.6 MB | [release.md](release.md#every-release), 2026-10-09 |
| Android `libksl.so`, arm64-v8a | gate: fails above 3,550,000 bytes, warns above 3,500,000 | `tools/check/size.sh`, step "android: size gate" of `tools/ci/local-matrix.sh` |

URLSession is part of the OS and adds nothing to an app. Cronet loaded from Google Play Services adds no Cronet binary
either: "the application doesn't need to pay the binary size cost of carrying Cronet"
([cronet-transport-for-okhttp][cronet-okhttp]). We have no sourced size for the others.

- TODO(measure): the size on iOS for 0.3.0: `tools/check/ios-size.sh` (the table above is of the 0.2.0 code; 0.3.0 adds
  HTTP/2 and WebTransport, and certificate compression is planned to add a compression library).
- TODO(measure): the measured arm64-v8a `libksl.so` size of 0.3.0, printed by `tools/check/size.sh` in the gate's size
  step, and the size of the `kuicksilver-native` JVM jar with its five JNI libraries.
- TODO(measure): the APK and IPA size delta of a minimal app with each stack (Kuicksilver's Ktor client, Cronet
  embedded, OkHttp, URLSession) on the same app, after R8 and app thinning. No tool in the repository does this yet.

## Maturity and user base

| | Who uses it, by its own account |
|---|---|
| **Kuicksilver** | No production users we know of. 0.2.0 was the first public release (2026-10-18); 0.2.0 and 0.2.1 are withdrawn and 0.3.0 is in preparation. One maintainer, no second reviewer ([GOVERNANCE.md](../GOVERNANCE.md)). |
| **Cronet** | YouTube, the Google app, Google Photos and Maps ([Android docs][cronet-android]). |
| **URLSession** | Apple's networking API on its OSes; HTTP/3 since iOS 15 ([TN3102][tn3102]). |
| **quiche** | Cloudflare's edge network for HTTP/3, Android's DNS resolver for DNS over HTTP/3, and curl as an HTTP/3 backend ([README][quiche-readme]). |
| **quic-go** | Caddy, Traefik, Syncthing, cloudflared, go-libp2p and others in its list ([README][quic-go-readme]). |
| **Netty QUIC** | Ktor's experimental HTTP/3 server engine since Ktor 3.6.0 (`enableHttp3`, `@ExperimentalKtorApi`, built on `netty-codec-http3`) ([Ktor source][ktor-h3]); our [engine interop bench](spec/interop.md#engine-interop-the-ktor-engines-against-other-http-stacks-jvm-2026-11-13) runs it. |
| **OkHttp** | Android itself: the platform's `HttpURLConnection` for http and https URLs is served by a repackaged copy of OkHttp (`com.android.okhttp`) ([AOSP URL.java][aosp-url]). |

What a production record finds is the bugs a test suite does not imagine. Kuicksilver does not have one yet. It
makes up part of the gap with verification (next sections), not all of it.

## API stability

Kuicksilver is pre-1.0: any 0.x release may break the API, and every break is listed in the
[CHANGELOG](../CHANGELOG.md). Within that, [stability.md](stability.md) marks every public declaration. Stable API goes
through a deprecation cycle before removal. Experimental API (`@ExperimentalKuicksilverApi`, opt-in) may change in any
minor release: 0-RTT, BBR and the whole HTTP/2 module among others ([What is experimental](stability.md#what-is-experimental)),
and the newer WebTransport, PROXY protocol and pluggable DNS resolver APIs ([CHANGELOG](../CHANGELOG.md)). ABI dumps are checked on
every change. The public API is frozen before 1.0.0 ([roadmap](roadmap.md#after-040-until-10)). The others have a
longer history; we have not compared their compatibility policies.

## Verification effort

Without known production use, the case for Kuicksilver rests on how it is checked. [How we verify](how-we-verify.md) has the
details:

- one row per RFC requirement, each naming the tests that pin it, checked by scripts
  ([rfc-compliance.md](spec/rfc-compliance.md));
- the QUIC Interop Runner against six QUIC stacks in both roles, h2spec, and the Ktor engines against Netty, CIO,
  OkHttp, the JDK's client and Netty's HTTP/3 codec;
- 34 fuzz targets, weekly in CI, with planted-bug checks of the reproducers;
- a 71-step local release gate on every target (76 for a release: interop and the Windows VM), and hosted CI;
- signed releases with an SBOM and provenance, and native libraries that rebuild byte for byte on a Mac.

Where it stops: no independent review (one maintainer), no physical iPhone run yet, SLSA Build Level 1, and the Linux
and Windows native libraries are not reproducible yet ([How we verify, What is not verified](how-we-verify.md#what-is-not-verified)).

## Other QUIC libraries for Kotlin

Other QUIC libraries a Kotlin project can use make different choices. [kwik](https://github.com/ptrd/kwik) is QUIC
written in Java with its own TLS 1.3, for the JVM, with HTTP/3 in the separate flupke library, under LGPL-3.0.
[quic-kmp](https://github.com/vitorpamplona/quic-kmp) is QUIC v1 and v2 written in Kotlin with its own TLS 1.3 over
the platform's JCA, for the JVM and Android, with HTTP/3, QPACK and WebTransport building blocks and no Ktor engine,
under MIT. [netonframework/quic](https://github.com/netonframework/quic) is a Kotlin port of quinn's QUIC v1 transport
on OpenSSL 4.0, for Kotlin/Native, the JVM and Android, with HTTP/3 in the separate
[netonframework/http3](https://github.com/netonframework/http3), under Apache-2.0. Netty's QUIC
codec ([netty/netty](https://github.com/netty/netty), formerly
[netty-incubator-codec-quic](https://github.com/netty/netty-incubator-codec-quic)) binds Cloudflare quiche and
BoringSSL through JNI on the JVM, and Ktor 3.6's experimental HTTP/3 server engine is built on it, under Apache-2.0.
Kuicksilver puts QUIC v1 and v2, HTTP/3 and QPACK in Kotlin on every target listed under
[Platforms](stability.md#platforms) (JVM, Android, iOS, macOS, Linux, Windows), uses OpenSSL built into its own native
library for TLS, ships Ktor client and server engines, and is licensed under Apache-2.0.

In protocol terms Kuicksilver implements QUIC v1 and v2 (RFC 9000/9001/9002/9369, datagrams of RFC 9221, path MTU
discovery of RFC 8899), HTTP/3 with QPACK (RFC 9114/9204, priorities of RFC 9218, Extended CONNECT and WebSockets of
RFC 9220, HTTP datagrams of RFC 9297), HTTP/2 (RFC 9113), TLS 1.3 over TCP, and Ktor 3.6 client and server engines on
top of them.

[cronet-android]: https://developer.android.com/develop/connectivity/cronet
[cronet-readme]: https://chromium.googlesource.com/chromium/src/+/HEAD/components/cronet/README.md
[cronet-okhttp]: https://github.com/google/cronet-transport-for-okhttp
[tn3102]: https://developer.apple.com/documentation/technotes/tn3102-http3-in-your-app
[urlsession]: https://developer.apple.com/documentation/foundation/urlsession
[okhttp-readme]: https://github.com/square/okhttp
[okhttp-protocol]: https://github.com/square/okhttp/blob/master/okhttp/src/commonJvmAndroid/kotlin/okhttp3/Protocol.kt
[wwdc-h3]: https://developer.apple.com/videos/play/wwdc2021/10094/
[scf]: https://github.com/swiftlang/swift-corelibs-foundation
[netty-quic-central]: https://repo1.maven.org/maven2/io/netty/netty-codec-native-quic/4.2.21.Final/
[netty-quic-ssl]: https://github.com/netty/netty/blob/4.2/codec-classes-quic/src/main/java/io/netty/handler/codec/quic/QuicSslContextBuilder.java
[netty-quic-path]: https://github.com/netty/netty/blob/4.2/codec-classes-quic/src/main/java/io/netty/handler/codec/quic/QuicPathEvent.java
[ktor-h3]: https://github.com/ktorio/ktor/blob/main/ktor-server/ktor-server-netty/jvm/src/io/ktor/server/netty/NettyApplicationEngine.kt
[aosp-url]: https://android.googlesource.com/platform/libcore/+/refs/heads/main/ojluni/src/main/java/java/net/URL.java
[quiche-ci]: https://github.com/cloudflare/quiche/blob/master/.github/workflows/stable.yml
[quic-go-ci]: https://github.com/quic-go/quic-go/blob/master/.github/workflows/unit.yml
[quic-go-xc]: https://github.com/quic-go/quic-go/blob/master/.github/workflows/cross-compile.sh
[quic-go-ech]: https://github.com/quic-go/quic-go/issues/3905
[netty-quic-pom]: https://github.com/netty/netty/blob/4.2/codec-native-quic/pom.xml
[netty-http3]: https://central.sonatype.com/artifact/io.netty/netty-codec-http3
[quiche-readme]: https://github.com/cloudflare/quiche
[quiche-lib]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs
[quic-go-readme]: https://github.com/quic-go/quic-go
[quic-go-0rtt]: https://quic-go.net/docs/quic/client/
[quic-go-mig]: https://quic-go.net/docs/quic/connection-migration/
