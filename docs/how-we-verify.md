<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# How we verify

Kuicksilver has no production users we know of, so you cannot judge it by its track record. This page shows what is checked
instead, where the checks live in the repository and what they found, so that you can decide whether to trust it, and
check the claims yourself. Each section names the files and scripts; the stage-by-stage process for contributors, with
every rule and every known blind spot of the checks, is in [process.md](process.md).

| Check | What it covers | Where | When it runs |
|---|---|---|---|
| [RFC conformance tables](#rfc-conformance-tables) | one row per requirement, with the tests that pin it | [rfc-compliance.md](spec/rfc-compliance.md), [spec/rfc/](spec/rfc/) | every change; format and test names checked by scripts |
| [Interop](#interop) | six QUIC stacks, h2spec, h3spec, the Autobahn\|Testsuite, other HTTP engines, browsers | [interop.md](spec/interop.md), `tools/interop/` | release gate (QUIC Interop Runner); weekly in CI |
| [Public HTTP/3 servers](#public-http3-servers) | the client against six public deployments, each a different QUIC implementation | [`public-h3.yml`](../.github/workflows/public-h3.yml), `PublicH3Main` | weekly in CI, by hand |
| [Fuzzing](#fuzzing) | 34 targets: every parser and the QUIC, HTTP/3 and HTTP/2 connection state machines | `tools/fuzz/` | weekly in CI; the corpus in every gate |
| [Planted bugs](#planted-bugs-instead-of-mutation-testing) | the fuzz reproducers and HTTP/1.1 and HTTP/3 targets still catch the bugs they found | `tools/fuzz/plants/`, `tools/fuzz/reproducers.txt` | weekly in CI, by hand |
| [The release gate](#the-release-gate) | every module on every target, sanitizers, emulator, Windows VM, Docker Linux | `tools/ci/local-matrix.sh` | every integration, every release |
| [Hosted CI](#hosted-ci) | the same steps on GitHub's runners, CodeQL, Scorecard | `.github/workflows/` | every push and pull request to `main` and `release/**` |
| [Soak](#soak) | resource growth over hours of mixed load | `kuicksilver-soak` | before a release |
| [Repository checks](#repository-checks) | bug classes that came back after review | `tools/check/` | every gate and the CI lint job |
| [Threat model](#threat-model) | attackers, threats, and a `negative_*` test per control | [threat-model.md](spec/threat-model.md) | every change that touches a threat |
| [Releases](#reproducible-builds-sbom-and-provenance) | signatures, SBOM, provenance, byte-for-byte rebuilds | [verifying.md](verifying.md), `tools/verify/verify-release.sh` | every release |

## RFC conformance tables

[rfc-compliance.md](spec/rfc-compliance.md) has one row per requirement or topic of every RFC and draft Kuicksilver
implements: QUIC (RFC 9000, 9001, 9002, 9369, 9221, 8899), TLS, HTTP/3 and QPACK, HTTP/2 and HPACK, WebTransport, and
the HTTP semantics the Ktor engines need. Each row has a status (✅ met, 🔶 subset or accepted deviation, ⬜ planned,
❌ not planned), the release it holds from, and a link to its section in one of the 55 details files under
[spec/rfc/](spec/rfc/): the requirement, the files that implement it, the tests that pin it, its history, what other
stacks do, and what is open. At this commit the summary has 244 rows: 230 met, 4 subset or deviation, 6 planned and
4 not planned. A 🔶 row says what is missing; nothing is called "partial" without saying what part.

Behaviour is checked against the RFC text, section by section, quoted rather than remembered; where the RFC leaves a
choice, the choice is compared with the sources of quic-go, quiche, ngtcp2, msquic, picoquic and quinn (QUIC), nghttp2
and Go's `x/net/http2` (HTTP/2), and OpenSSL and BoringSSL (TLS) ([process.md, stage 3](process.md#3-where-the-rfc-leaves-a-choice-reference-stacks)).
Two scripts keep the tables honest: `tools/check/rfc-table.sh` checks the format and every link, and
`tools/check/rfc-tests.py` fails when a test a ✅ section names does not exist, or when a ✅ section names none.
Whether the tests really pin what a row claims is a matter of review, not of a tool. Departures from a standard made
only for a peer that breaks it are listed with their removal condition in [compat-shims.md](spec/compat-shims.md).

## Interop

| Suite | Peers | Result | Date, code | Source |
|---|---|---|---|---|
| QUIC Interop Runner, JVM image | msquic, ngtcp2, picoquic, quic-go, quiche, quinn; Kuicksilver as server and as client; 21 cases | 227 of the 237 cells both sides support are green; every required cell green | 2026-10-13, 0.2.0 code, runner `740c05a` | [interop.md](spec/interop.md#interop-matrix-020-quic-interop-runner-740c05a-2026-10-13) |
| QUIC Interop Runner, Kotlin/Native `linuxArm64` image | the same six, both roles, 9 cases | 96 of 99 | same | same |
| h2spec 2.6.0, the HTTP/2 server | JVM, `macosArm64` and `linuxX64` servers | 146 of 146 cases on each | 2026-11-06 (`linuxX64`: 2026-11-14) | [interop.md, h2spec](spec/interop.md#h2spec-the-http2-server-h2spec-260-2026-11-06) |
| h3spec v0.1.15, the HTTP/3 server | JVM, `macosArm64` and `linuxX64` servers | 85 of 86 cases on each; the 86th is h3spec's error (RFC 9114 §7.1 asks for the H3_FRAME_ERROR the server sends) | 2026-11-26 | [interop.md, h3spec](spec/interop.md#h3spec-the-http3-server-h3spec-v0115-2026-11-26) |
| Autobahn\|Testsuite 25.10.1, WebSockets (RFC 6455, RFC 7692) | the server and the client engine: `linuxX64` both and the JVM client in the release gate, all four in hosted CI (the JVM server only there: Docker Desktop drops an occasional connect to the host) | 517 cases each way; every one OK or INFORMATIONAL but those the script records with the RFC text that allows their verdict (Ktor's session answering a Close before the application's echo, the optional `*_max_window_bits` parameters); 2 bugs of ours found and fixed | 2026-11-26 | [interop.md, Autobahn](spec/interop.md#autobahntestsuite-the-websocket-server-and-client-25101-2026-11-26) |
| Engine interop | Ktor's Netty (HTTP/1.1, HTTP/2, HTTP/3) and CIO engines, plain Netty, OkHttp, the JDK's HttpClient, Netty's HTTP/3 client; 19 HTTP scenarios per pair and a WebSocket suite | every pair passes (where a peer behaves differently, the test asserts our side and the page describes the peer's); 3 bugs of ours found and fixed | 2026-11-13 | [interop.md, Engine interop](spec/interop.md#engine-interop-the-ktor-engines-against-other-http-stacks-jvm-2026-11-13) |
| WebSockets over HTTP/2 (RFC 8441) | Node.js 24 (nghttp2) both ways, Chrome 157 | pass | 2026-11-12 | [interop.md](spec/interop.md#websockets-over-http2-rfc-8441-2026-11-12) |
| WebTransport | Chrome 155 (headless, automated), Firefox 158 (by hand) | pass; Safari not run yet | 2026-10-22 and 2026-10-23 | [interop.md](spec/interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23) |

Every red cell of the runner matrices is analysed, cell by cell, in [interop.md](spec/interop.md).
`tools/interop/run-local.sh` runs the matrix locally (`--check-required` fails on a red cell listed in
`tools/interop/required.json`); the runner is pinned in `tools/interop/runner.lock`, and `tools/interop/peer-images.sh`
makes sure every peer image is really present, so a peer that cannot run fails the run instead of turning its cells
red without a cause. The release gate runs both images against all six peers (`--with-interop`), and hosted CI runs the
runner weekly. The engine interop bench, `kuicksilver-engine-interop`, runs in every gate and in CI. The server engine
also runs Ktor's own engine contract suites (adapted from Ktor 3.6.0) in its common tests, so on every target.
h3spec (`tools/interop/h3spec.sh`) and the Autobahn|Testsuite (`tools/interop/autobahn.sh`) run in every gate and in
hosted CI, as h2spec does (the JVM WebSocket server only in hosted CI, on Linux): each fails on a case that does not pass, except the cases it lists with the RFC text that
allows them, and on a change in the number of cases. Their durations in hosted CI are to be recorded after the first run there
([interop.md](spec/interop.md#autobahntestsuite-the-websocket-server-and-client-25101-2026-11-26)).

- TODO(measure): the runner matrix on the 0.3.0 code: `tools/ci/local-matrix.sh --with-interop` (or
  `tools/interop/run-local.sh` per image), then the tables of [interop.md](spec/interop.md) and
  [reliability.md](reliability.md) (`tools/report/reliability.sh`).

## Public HTTP/3 servers

[`public-h3.yml`](../.github/workflows/public-h3.yml) runs the Ktor client against public HTTP/3 deployments weekly
(Wednesday) and by hand: `./gradlew --max-workers=2 :kuicksilver-ktor-client:publicH3Check` runs `PublicH3Main` (in the
module's `jvmTest` sources, never part of `check` or `jvmTest`) and writes a summary table, `results.json` and the qlog
traces of every attempt that did not pass. It needs real UDP and DNS and a network that may be used to contact these
servers, so it runs on GitHub's runners, or by hand where UDP to port 443 is open; never in the release gate. The
workflow compiles first (a build that failed on a dependency is retried) and then runs the check once, offline for
Gradle, so a retry never contacts the servers a second time. Every request names the check in its `User-Agent`
(`kuicksilver-public-h3/<version>` and a link to this section). The run stops starting checks after 40 minutes and
writes what it has; after every target it writes its results so far, so a job cut short still leaves them.

| Target | Host | QUIC implementation | Why this one |
|---|---|---|---|
| Cloudflare | `cloudflare-quic.com` | Cloudflare quiche | Cloudflare's own HTTP/3 page; `/cdn-cgi/trace` reports what the server saw (`http=http/3`, `sni=encrypted`); its HTTPS record carries `alpn=h3` and an `ech` configuration (checked 2026-11-25) |
| Google | `www.google.com` | Google QUICHE | the largest HTTP/3 deployment, the stack Chrome talks to |
| Meta | `www.facebook.com` | mvfst | a third large independent stack; also announces `h3` in its HTTPS record (checked 2026-11-25) |
| Fastly | `www.fastly.com` | quicly (H2O) | the CDN's own site on its QUIC stack |
| LiteSpeed | `www.litespeedtech.com` | LSQUIC | the stack behind many shared hosts |
| nginx | `quic.nginx.org` | nginx QUIC | nginx's own HTTP/3 page, the server many origins run |

Every target announced `h3` in `Alt-Svc` (checked 2026-11-25). Akamai is left out: `www.akamai.com` answered scripted
clients with a bot wall (checked 2026-11-25), and its QUIC stack derives from Google's. Test servers run by one person
are left out too: they come and go. Any status counts as an answer (no redirect is followed), so a consent page or a bot
wall served over HTTP/3 still checks the protocol.

| Check | How | Pass when (from the client's own diagnostics) |
|---|---|---|
| HTTP/3 | `Http3Discovery.H3Only` GET | the response is `HTTP_3_0`, its `ProtocolDiagnostics.connection` is a `QuicConnectionSnapshot`, the connection listener heard a completed handshake with ALPN `h3` on a QUIC version we offered (the summary names it, v1 or v2); on Cloudflare the trace also says `http=http/3` (`http/1.1`, `http/2` or `h2` there fail; a missing or unknown value warns) |
| Alt-Svc | `Auto`, a new client | the first answer came over TCP (HTTP/2 expected; HTTP/1.1 is a warning) with `h3` in `Alt-Svc`, and a later request went over HTTP/3 with `alternativeSource = AltSvc` |
| 0-RTT | `http3 { earlyData { enabled = true } }`, the connection dropped after two requests | the new connection's `onZeroRtt` reports `Accepted`; `Rejected` or no early-data ticket is "n/a" (the server's choice, RFC 9001 section 4.6.2) |
| Migration | `QuicConnection.migrate` to a new socket on a new local port | the next request goes on the same connection (`reused`) and `pathChanges` is at least 1; a server that sent `disable_active_migration` or uses zero-length connection IDs is "n/a"; a GOAWAY after the move, a path that did not validate, or no unused connection ID of the server's for the new path warns; any other failure of `migrate` fails |
| ECH | Cloudflare only: the `ech` of the HTTPS record (DNS over HTTPS), `tls { ech { configLists } }`, `H3Only` | `/cdn-cgi/trace` says both `sni=encrypted` and `http=http/3`; `sni=plaintext` or a known other `http=` fails; a missing `http=` or `sni=` line, or a value the check does not know, warns |

**Failure policy.** Each check is judged `pass`, `n/a`, `warn` or `FAIL`. A server that changed or could not be reached
is a warning annotation and never a red job:

- a failed name lookup or TCP connect, no QUIC packet back, a stateless reset, `Alt-Svc` without `h3` any more;
- a QUIC close by the server with NO_ERROR, INTERNAL_ERROR, CONNECTION_REFUSED, INVALID_TOKEN (a token the server no
  longer accepts after a key rotation, RFC 9000 section 8.1.3), APPLICATION_ERROR, AEAD_LIMIT_REACHED or NO_VIABLE_PATH;
- an HTTP/3 close by the server with H3_NO_ERROR, H3_INTERNAL_ERROR, H3_REQUEST_REJECTED, H3_REQUEST_CANCELLED,
  H3_CONNECT_ERROR, H3_VERSION_FALLBACK or a code outside RFC 9114 (read as H3_NO_ERROR);
- these TLS alerts from the server, about itself or its policy: `close_notify` (0), `access_denied` (49),
  `internal_error` (80), `user_canceled` (90), `unrecognized_name` (112), `unknown_psk_identity` (115: a ticket the
  server no longer accepts), `certificate_required` (116), `no_application_protocol` (120);
- an HTTP/2 reset or GOAWAY from the server with NO_ERROR, INTERNAL_ERROR, REFUSED_STREAM, CANCEL, CONNECT_ERROR or
  HTTP_1_1_REQUIRED; an HTTP/2 connection that ended without GOAWAY (RFC 9113 section 6.8 makes GOAWAY a SHOULD) when
  its cause chain is a transport failure, judged link by link: every cause is a network exception, a plain `IOException`
  with one of the library's peer and path messages (the peer closed the connection, no PING acknowledgement, a health
  PING not answered, the socket timeout expired; listed with their source lines in `PublicH3Verdicts.kt`, and a test
  fails when one of them changes), a TLS transport closure, or Ktor's `ClosedByteChannelException`, which passes the walk
  on without deciding it; and at least one link is one of the first three;
- a TLS transport closure: a TLS failure without an OpenSSL error code that either has no cause and says the transport
  closed (during the handshake, or without close_notify: a real FIN), or whose cause chain is a transport failure as
  above;
- an expired, not yet valid, revoked or misnamed certificate; an unknown issuer too, with a note: the runner's trust store
  can lag behind a CA a server just moved to, a known source of false alarms, so its qlog is kept for a look;
- the exceptions a network causes: `java.net.SocketException`, `java.net.SocketTimeoutException`, `java.io.EOFException`,
  `java.nio.channels.ClosedChannelException` and Ktor's `HttpRequestTimeoutException`.

The job fails when the client is wrong:

- a server closed with a code that blames the client: any other QUIC transport error (PROTOCOL_VIOLATION,
  FRAME_ENCODING_ERROR, TRANSPORT_PARAMETER_ERROR, ...), any other TLS alert (`decode_error`, `illegal_parameter`, ...),
  any other HTTP/3 code (H3_FRAME_UNEXPECTED, H3_SETTINGS_ERROR, H3_EXCESSIVE_LOAD, which a server sends about its peer's
  behaviour, ...), any other HTTP/2 code (PROTOCOL_ERROR, COMPRESSION_ERROR, FRAME_SIZE_ERROR, FLOW_CONTROL_ERROR,
  STREAM_CLOSED, ENHANCE_YOUR_CALM, which says the peer "is exhibiting a behavior that might be generating excessive
  load", ...); a stream reset or stop is read through its HTTP/3 meaning;
- a QPACK error (0x200 to 0x202) from either side; the client closed or reset with an error of its own (it judged a
  widely deployed server's packets invalid); an HTTP/2 connection that ended without GOAWAY over any other cause chain
  (a runtime exception on the way, even over a socket failure; another exception of this library; a plain `IOException`
  of our own close: "the connection is closing", "the HTTP/2 connection was closed by the client", "the TLS socket is
  closed") or none; a malformed response; every other TLS failure: one with an OpenSSL error code, and one without that
  is no transport closure (an unexpected ksl state, a resumed session without a cached chain, refused ciphertext, a
  renegotiation, a failure of the ksl shim, a "transport closed" over our own close, the "transport failure" wrapper over
  anything but a transport failure);
- a server that answered our Initial but whose handshake never completed; a stall on a connection whose own handshake
  had completed (the attempt's deadline, or the engine's stall detection). The stalled connection is the one the
  stalled call's diagnostics name (the engine's event listener notes it at the call's end or failure); a call that
  stalled before any connection was its is judged by the attempt's connections still open, the limit of what the
  listeners can tell;
- a certificate rejected for another reason; ECH rejected with a configuration fresh from DNS;
- a contradiction in our diagnostics (an `H3Only` call over TCP, a version we never offered, an `Alt-Svc` the client did
  not learn, a server trace that names another protocol);
- any other exception: every other exception of this library (`QuicException.ConnectionLost.Internal`,
  `TlsException.Config`, `Http3Exception.Settings`, a field section too large, ...) and every other type.

A check that does not pass runs once more on a new client: `FAIL` stands only when both attempts blame the client; a pass
on the second attempt, or a failure followed by "n/a", is a warning that names the first failure. Two rules work across
targets. A check of HTTP/3, Alt-Svc and 0-RTT that ran on three or more reachable targets and passed on none of them
fails on all of them (the reason states on how many it ran), since every deployment changing in the same week is less likely than a regression of ours (Initials no server
answers, an `Alt-Svc` parser that learns nothing, resumption that never offers 0-RTT). Migration fails the same way when
three or more reachable targets did not refuse it and it passed on none. A control decides whether these rules apply:
before the checks, a datagram built by hand from the version-independent invariants (RFC 8999) with a version reserved
to force Version Negotiation (RFC 9000 section 15) goes to port 443 of every target, without our QUIC stack. When no
target answers it, the runner's network blocks QUIC and the rules are not applied; the summary lists the versions each
target's Version Negotiation named. A runner that reaches no target at all (no name lookup, no TCP) stays a warning, and
a check the 40-minute deadline skipped is a warning the rules leave alone. The rules are `classify`, `combine` and
`escalate` in `PublicH3Verdicts.kt`, with the trace and migration judgements in `PublicH3Probe.kt`, each tested on built
outcomes in `PublicH3VerdictsTest` (part of the ordinary `jvmTest`). The annotations come one per target and level,
its checks' reasons joined (GitHub shows at most ten of each type per step).

A known blind spot: INVALID_TOKEN from a server is a warning, since a token from NEW_TOKEN may stop being accepted
after a key rotation (RFC 9000 section 8.1.3). But a client that sends a Retry token back wrongly gets the same code, and
neither the diagnostics nor the qlog trace (no event for a Retry received) show whether the Initial carried a Retry
token, so that mistake of ours would show here as a warning only. The QUIC Interop Runner's `retry` case covers it.

What the runners cannot show: a migration between two networks (a runner has one interface; the check moves to a new
local port, which the server sees as a new address through the runner's NAT) and a server's behaviour as seen from other
networks and regions. The qlog traces name the runner's address and the connection IDs, both of a throwaway machine;
the artifacts keep them 14 days.

## Fuzzing

`tools/fuzz/campaign.sh list` names 34 targets: 33 Jazzer targets over the QUIC frame, packet, transport parameter
and reassembly code, two stateful fuzzers of whole QUIC connections (with real TLS and with null crypto) and of 0-RTT,
TLS ClientHello scanning, HTTP/3 frames, capsules and QPACK, an HTTP/3 connection, HTTP/2 frames and HPACK and both
sides of an HTTP/2 connection, HTTP/1.1 requests and responses, WebSocket inflate and limits, HTTPS records, the PROXY
protocol header; and a libFuzzer harness of the C parsing code in `ksl` (`tools/fuzz/ksl/`).

- **Campaigns.** [`fuzz.yml`](../.github/workflows/fuzz.yml) fuzzes every target on its own runner, 2 hours per target,
  every week. A finding fails the job and stays private until it is fixed: no reproducer or log is uploaded, since the
  artifacts of a public repository are public. Locally, `tools/fuzz/campaign.sh` runs resumable slices.
- **Corpus.** The grown corpora are minimized into `tools/fuzz/corpus/` (26 targets, 11,878 inputs at this commit), and
  the release gate replays them, with each target's regression inputs, as tests.
- **Findings.** A crash becomes a committed input, a unit test and a fix. 20 inputs, for 17 bugs, are recorded in
  `tools/fuzz/reproducers.txt`.

- Planned for 0.4.0 ([roadmap](roadmap.md#040-planned)): differential fuzzing of the QUIC code against quiche and
  quic-go.
- TODO(measure): fuzzing hours per target for 0.3.0: `tools/fuzz/campaign.sh status` after the campaign, read by
  `tools/report/reliability.sh` from `build/fuzz-campaign/stats.tsv` (the current [reliability.md](reliability.md)
  says "not measured in this gate").

## Planted bugs instead of mutation testing

No general mutation-testing tool (one that mutates the code at random and counts the tests that notice) runs on
Kuicksilver. What runs instead is targeted: every recorded fuzz reproducer has a plant, a small patch that puts its bug
back (`tools/fuzz/plants/`), and `tools/fuzz/reproducers-verify.sh` applies each plant in turn: a live reproducer must fail
again with its recorded failure and its guard test, where it names one, must fail too; for the dead entries, whose
input no longer reaches the bug, the input must still pass and the guard test must fail. `tools/fuzz/planted-check.sh` and
`tools/fuzz/h3-planted-check.sh` plant known HTTP/1.1 and HTTP/3 bugs and require the fuzz targets to catch them. Every
security check also has a `negative_*` test that fails when the check is removed ([threat model](#threat-model)). This
is mutation testing of the security checks only ([threat-model.md, section 8](spec/threat-model.md#assurance-case)).

- Planned for 0.4.0 ([roadmap](roadmap.md#040-planned)): a mutation score of the protocol cores, starting with
  HTTP/3. That needs a mutation tool for Kotlin set up first (none is in the build); there is no number to give.

## The release gate

[`tools/ci/local-matrix.sh`](../tools/ci/local-matrix.sh) runs on the maintainer's Mac with Docker, an Android emulator
and a Windows 11 VM. A release needs a passing run of the release commit, with every step: the release script
refuses anything else ([release.md](release.md)). `tools/ci/local-matrix.sh --dry-run` lists the steps:

| Steps | Count |
|---|---|
| default | 79 |
| for a release, with `--with-interop --with-windows` | 84 |
| with `--with-browser` too (Chrome WebTransport) | 85 |

| Platform or area | What runs |
|---|---|
| JVM on macOS | every module's tests, the engine interop bench, the samples, the coverage report; the changed modules' tests on JDK 17 and 25 |
| JVM on Linux x64 and arm64 | every module's suite in Docker against the manylinux `libksl.so`; the system-OpenSSL mode |
| JVM on Windows (release run) | every module's suite in the Windows 11 VM against the mingw-w64 dll |
| Android | the AAR, its size gate, 16 KiB page alignment, R8 keep rules, the loops ART 7 can deoptimize ([art7-deopt-loops.md](spec/art7-deopt-loops.md)), the device tests on the emulator, connection migration against a server on the host; the changed modules' device tests on an API 24 emulator |
| macOS and iOS | `macosArm64` tests, every module's `iosSimulatorArm64` tests on the simulator, `iosArm64` compiled |
| Linux (Kotlin/Native) | the `linuxX64` and `linuxArm64` test executables of every module in Docker, glibc floors, h2spec, h3spec and the Autobahn\|Testsuite, the deployment guide's commands with `curl --http3-only` |
| Windows (Kotlin/Native) | the `mingwX64` test executables are linked here and run in hosted CI |
| C (`ksl`) | the C tests under ASan and UBSan, and under ThreadSanitizer, on macOS; on Linux x64 and arm64 in Docker |
| Simulation | 200 seeded QUIC transfers through the network simulator on random links (delay, loss, reordering, MTU) |
| Documentation, build integrity | the repository checks, dependency verification, ABI dumps, the API reference with warnings as errors |
| Reproducibility | OpenSSL, `libksl` and the JNI library built twice from two paths and compared |
| Interop (release run) | both interop images against the six QUIC peers, required cells green |

The list of what each step does is in [process.md, stage 5](process.md#5-integration-and-the-local-gate).

## Hosted CI

[`build.yml`](../.github/workflows/build.yml) runs the counterpart of the gate on GitHub's runners on every push and
pull request to `main` and `release/**`, weekly, and by hand: lint; Linux x64 and arm64 (C tests, JVM suites, system
OpenSSL; on x64 the Autobahn|Testsuite against the JVM WebSocket server and client); the Kotlin/Native Linux executables
(with h2spec, h3spec and the Autobahn|Testsuite against the linuxX64 ones); Windows (the `mingwX64` test executables, the C tests, the JVM suites);
Apple (ABI dumps, ASan C tests, JVM suites, the double build, `macosArm64` and `iosSimulatorArm64` suites); Android on
API 24 and 35 emulators; JDK 17 and 25; the jar with all five JNI libraries; a sample built from a local publication;
and, weekly, the QUIC Interop Runner. The other workflows: [`codeql.yml`](../.github/workflows/codeql.yml) (CodeQL over
the C shim and the Kotlin JVM code), [`scorecard.yml`](../.github/workflows/scorecard.yml) (OpenSSF Scorecard),
[`fuzz.yml`](../.github/workflows/fuzz.yml) (above), [`gradle-wrapper.yml`](../.github/workflows/gradle-wrapper.yml),
[`perf.yml`](../.github/workflows/perf.yml) (throughput floors, by hand),
[`public-h3.yml`](../.github/workflows/public-h3.yml) (the client against public HTTP/3 servers, weekly),
[`interop-image.yml`](../.github/workflows/interop-image.yml) (publishes a release's interop images, by hand),
[`pages.yml`](../.github/workflows/pages.yml) (the documentation site) and
[`release.yml`](../.github/workflows/release.yml) (a hosted release, not used). Hosted CI is read, not enforced: no
branch rule requires it to be green ([process.md, stage 6](process.md#6-hosted-ci)).

## Soak

`kuicksilver-soak` runs the whole stack on real UDP for hours under a mix of transfers, aborts, idle timeouts,
stateless resets, migrations, 0-RTT, churn and Ktor requests, and samples memory, descriptors, threads, native objects
and the library's own tables. A run passes when every series stays flat after warm-up, every countable resource returns
to its idle baseline, and unexpected failures stay under 0.5 %.

| Run | Result | Source |
|---|---|---|
| JVM, 2 h, 8 clients | PASS: 186,186 iterations, 0 unexpected; 43 of 43 metrics flat | [reliability.md](reliability.md#soak), read by the gate of 2026-11-06 (run date not recorded) |
| Kotlin/Native `linux-arm64`, 2 h, 8 clients | PASS: 201,095 iterations, 0 unexpected; 40 of 40 metrics flat | same |
| 0.2.1 release: Kotlin/Native 24 h, JVM 37 h | passed | [process.md, stage 7](process.md#7-before-a-release-soak-fuzzing-benchmarks) |

- TODO(measure): the 24–72 hour soak of the 0.3.0 release candidate, regenerated into [reliability.md](reliability.md)
  by `tools/report/reliability.sh`.

## Numbers

Benchmarks are measurements on one host, not promises; read the caveats of each page before quoting them.

| What | Result | Source, date |
|---|---|---|
| Goodput, 10 MB in the runner's simulator (10 Mbit/s link), Kuicksilver server | 9273–9434 kbit/s median against quiche, quinn and msquic clients | [benchmarks.md, Goodput](benchmarks.md#goodput), 2026-10-21 |
| Server CPU per GB | JVM 2.72 s, Native 3.47 s; msquic 1.86 s (emulated), quiche 11.47 s (emulated), quinn 15.56 s | [benchmarks.md, CPU per GB](benchmarks.md#cpu-per-gb), 2026-10-21 |
| Handshakes per second | JVM 1750, Native 1524; quinn 3452, msquic 3543 (emulated), quiche 228 (emulated) | [benchmarks.md](benchmarks.md#handshakes-per-second), 2026-10-21 |
| Idle HTTP/3 connection, server side, JVM heap | 80.6 KB | [benchmarks.md, Memory](benchmarks.md#memory-p5-2026-11-06), 2026-11-06 |
| One connection over loopback | 250–253 MiB/s | [benchmarks.md](benchmarks.md#one-connection-over-loopback-2026-11-08), 2026-11-08 |
| HTTP/3 vs TCP, 10 MiB, 100 ms RTT, 3 % loss | HTTP/3 96.7 s; fastest TCP client 123.0 s | [why-quic.md](why-quic.md#downloads-under-delay-and-loss), 2026-11-09 |
| Time to first byte, 100 ms RTT | HTTP/3 225 ms, 0-RTT 114 ms, Kuicksilver HTTP/2 321 ms, OkHttp HTTP/2 469 ms | [why-quic.md](why-quic.md#connection-setup), 2026-11-09 |
| iOS app size added (Release arm64, linked) | 5.60 MB (about 3.4 MB if the app already ships Kotlin) | [ios.md, Size](guide/ios.md#size), 2026-10-14, 0.2.0 code |
| Android AAR of `kuicksilver-native`, three ABIs | about 3.6 MB | [release.md](release.md#every-release), 2026-10-09 |
| `negative_*` tests | 782 | [reliability.md](reliability.md#negative-tests), 2026-11-06 |

Still to measure (the tool that produces each):

- TODO(measure): the handshake rate after the 0.3.0 server changes: `tools/bench/run-table.sh --phases handshakes`.
- TODO(measure): the size on iOS for 0.3.0 (`tools/check/ios-size.sh`) and the arm64-v8a `libksl.so` of 0.3.0
  (`tools/check/size.sh`, printed by the gate's "android: size gate" step).

Planned for 0.4.0 ([roadmap](roadmap.md#040-planned)): benchmarks against OkHttp beyond `tools/bench/why-quic.sh` (which
covers OkHttp's HTTP/1.1 and HTTP/2 over an emulated network), against Cronet and URLSession on a phone and against
Netty's HTTP/3 server, and high-bandwidth benchmarks against the peer QUIC stacks on gigabit links. No tool in the
repository does these yet.

## Repository checks

Bug classes that came back after review are caught by scripts in `tools/check/`, each with negative controls that try
to get past it (`<name>-test.sh`), in every gate and in the CI lint job. Among them: a test that no runner would run
(`test-discovery.py`, and `test-bytecode.py` on the compiled classes), a drop in the number of tests (`test-count.py`),
new sleeps in tests (`test-sleeps.py`), a deadline or a `select` whose race has no verdict (`deadline-sites.py`,
`select-races.py`), a race test without a seam that forces its order (`race-tests.py`), a ✅ RFC row whose tests are
gone (`rfc-tests.py`), documentation that names a file, test, symbol or Gradle task that does not exist
(`doc-refs.sh`, `code-refs.py`, `links.sh`), guide code that differs from the tests that compile it (`guide-sync.sh`),
and, for releases, native libraries with the wrong OpenSSL, exports or a home-directory path (`native-release.sh`,
`build-paths.py`). What each check catches and what it cannot see: [process.md, Repository checks](process.md#repository-checks).

## Threat model

[threat-model.md](spec/threat-model.md) lists the assets, the attackers and 28 groups of threats with their
mitigations, from amplification and resource exhaustion to 0-RTT replay, parsing errors and the supply chain. Every
control has a `negative_*` test that fails when the control is removed;
[section 5](spec/threat-model.md#5-negative-controls--release-gate-checklist) is the checklist the release gate runs,
[section 4](spec/threat-model.md#4-what-we-do-not-protect-against) says what is not protected against, and
[section 8](spec/threat-model.md#assurance-case) is the assurance case. Vulnerabilities are reported privately
([SECURITY.md](../SECURITY.md)).

## Reproducible builds, SBOM and provenance

Every artifact on Maven Central is signed with the release key. Each GitHub release carries a CycloneDX SBOM (with the
statically linked OpenSSL as a component) and a signed provenance statement (SLSA provenance v1). The native libraries
built on a Mac (the macOS dylibs, the Apple and Linux Kotlin/Native archives, the Android `libksl.so`) are reproducible:
for 0.2.0, all 20 files `tools/verify/verify-release.sh` rebuilds from the tag were byte-identical to the ones on Maven
Central (2026-10-22). [verifying.md](verifying.md) shows how to check a release yourself and what each check proves.

## What is not verified

- **Independent review.** One maintainer reviews every change ([GOVERNANCE.md](../GOVERNANCE.md)); nobody else has
  reviewed the code.
- **Production traffic.** No deployment we know of has run it yet.
- **A physical iPhone.** iOS is tested on the simulator only ([ios.md, Device checklist](guide/ios.md#device-checklist)).
- **Build provenance** is SLSA Build Level 1: the same person and machine build, describe and sign.
- **Not reproducible yet:** the Linux and Windows JNI libraries, the `mingwX64` archives and the Kotlin outputs
  ([verifying.md](verifying.md#not-reproducible-yet-and-why)). A rebuild on a second, independent machine has not been
  recorded.
- **Hosted CI is not required** to be green before a change lands; the local gate is.
- **JVM on Intel Macs.** The `osx-x86_64` JNI library is built and its exports checked, but no test runs on it.
- **Kotlin/Native on Windows.** The `mingwX64` test executables are only linked by the gate; they run in hosted CI,
  which a release does not require.
- **A physical Android phone.** Device tests run on emulators only.
- **Connection migration between real networks against public servers.** The weekly public HTTP/3 check moves a
  connection to a new local port only; a move between networks is tested on the Android emulator against our own server.
- **Safari.** WebTransport with Safari has not been run.
- **The 0.3.0 code** has not yet been through the QUIC Interop Runner, a 24–72 h soak, the benchmarks or a measured
  fuzz campaign: the figures above are from 0.2.0 and 0.2.1 or from early-November gates (see the TODOs).
- **No mutation score** ([Planted bugs](#planted-bugs-instead-of-mutation-testing)).
