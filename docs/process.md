<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# How a change is checked

What every change goes through before it reaches a release, and what happens after. Each stage names the script or
document that implements it, so every statement here can be checked against the repository. Where a stage is a
practice that no tool enforces, or is partial, this page says so.

| Stage | What | Where | Enforced by a tool |
|---|---|---|---|
| [1](#1-a-test-that-fails-before-the-fix) | A test that fails before the fix | [CONTRIBUTING.md, Tests](../CONTRIBUTING.md#tests) | no (the test itself, once written, runs everywhere) |
| [2](#2-review-the-code-and-the-rfc-text) | Code review and a check against the RFC text | [CONTRIBUTING.md, Review checklist](../CONTRIBUTING.md#review-checklist) | no |
| [3](#3-where-the-rfc-leaves-a-choice-reference-stacks) | Comparison with reference stacks where the RFC leaves a choice | `docs/spec/rfc/<rfc>.md`, peer notes; commit messages | no |
| [4](#4-the-rfc-compliance-matrix-and-the-threat-model) | The RFC compliance matrix and the threat model | [rfc-compliance.md](spec/rfc-compliance.md), [threat-model.md](spec/threat-model.md) | format and references: yes; content: review |
| [5](#5-integration-and-the-local-gate) | Integration branch and the local gate on every target | [`tools/ci/local-matrix.sh`](../tools/ci/local-matrix.sh) | yes |
| [6](#6-hosted-ci) | Hosted CI on pushes and pull requests to `main` and `release/**` | [`.github/workflows/build.yml`](../.github/workflows/build.yml) | runs automatically; no branch protection requires it green yet |
| [7](#7-before-a-release-soak-fuzzing-benchmarks) | Soak, fuzzing campaigns, benchmarks | `kuicksilver-soak`, `tools/fuzz`, [benchmarks.md](benchmarks.md) | run by hand; the verdicts are computed |
| [8](#8-the-release) | Signed artifacts, SBOM, provenance, verification | [release.md](release.md), [verifying.md](verifying.md) | yes (`tools/release/local-release.sh` refuses) |
| [9](#9-after-a-release) | Vulnerability handling and OpenSSL updates | [SECURITY.md](../SECURITY.md) | no (commitments) |

## 1. A test that fails before the fix

A bug fix starts with a test that fails for the reason of the bug (RED), then the fix makes it pass (GREEN); the pull
request or the commit message names the test and how it failed ([CONTRIBUTING.md, Tests](../CONTRIBUTING.md#tests)). Every security check has a `negative_*` test that fails when the check is removed; the
threat model lists them. The rule for new tests is no waiting with `sleep` or `delay`: virtual time, the seeded
network simulator in `kuicksilver-testing` or `MemoryNetwork`, so a failure reproduces from its seed; some older tests
still poll with a deadline. A new test never uses `delay()` as synchronization: it waits for the event itself (a
`CompletableDeferred`, a channel, a job), and `tools/ci/flake-hunt.sh` reruns a suite 20 times under CPU load to find
the tests that still wait with a delay.

No tool checks that a test failed before the fix; reviewers ask for it, and the pull request template has a box for it
([`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md)). A failing existing test is first treated
as a bug in the code; a test is changed only when it is wrong or fragile, and the commit says why.

## 2. Review: the code and the RFC text

Every change goes through two review passes:

- **A code review** against the [Review checklist](../CONTRIBUTING.md#review-checklist): the classes of bugs this
  project has shipped or nearly shipped (a deadline on every wait on a peer, bounded memory per peer, every resource
  closed on every path, no silent fallbacks, documentation claims backed by code, tests that are not flaky by
  construction, and more). New classes found in review or after a release are added to that list.
- **An RFC check** of protocol behaviour against the text of the RFC, quoted section by section rather than from
  memory: every MUST and SHOULD the change touches is met, and the rows of the compliance matrix (stage 4) say so.
  A deviation from a MUST or SHOULD is not accepted as "partial"; it is fixed, or the row says it is not met.

Findings are fixed in their own commits, with a failing test where the finding is a behaviour a test can show (stage 1),
and the fix is reviewed again.

What is not in place: reviews are not yet recorded on GitHub pull requests (changes are integrated locally, stage 5),
and there is no second maintainer. `.github/CODEOWNERS` still names a placeholder team.

## 3. Where the RFC leaves a choice: reference stacks

When an RFC allows several behaviours (a limit, a timer, what to do with a peer that is legal but unusual), the
choice is compared with what established implementations do, from their sources:

- QUIC and HTTP/3: quic-go, quiche, ngtcp2 and msquic, and where relevant picoquic and quinn;
- HTTP/2 and HPACK: nghttp2 and Go's `x/net/http2` (also Netty and OkHttp);
- TLS: OpenSSL and BoringSSL.

The comparison cites the peer's file and line, and is recorded in the commit message and in the notes on peers of the
row's details file (for example [docs/spec/rfc/9113.md](spec/rfc/9113.md), [docs/spec/rfc/9000.md](spec/rfc/9000.md)).
This is a practice of review, not a check a tool runs. The same six QUIC stacks are the peers of the interop runs
(stage 5); [benchmarks.md](benchmarks.md) compares with three of them (quiche, quinn and msquic).

## 4. The RFC compliance matrix and the threat model

- [docs/spec/rfc-compliance.md](spec/rfc-compliance.md) has one row per requirement or topic (met, feature subset,
  planned, not planned) and links each row to its section in `docs/spec/rfc/<rfc>.md`: the requirement, the files that
  implement it, the tests that pin it, history, notes on peers and open items. A change of behaviour updates the row
  and its details in the same commit. [`tools/check/rfc-table.sh`](../tools/check/rfc-table.sh) checks the table format
  and that every details link and anchor exists; whether a row is true is a matter of review (stage 2).
- [docs/spec/threat-model.md](spec/threat-model.md) lists the assets, attackers, threats and mitigations, and in
  [section 5](spec/threat-model.md#5-negative-controls--release-gate-checklist) the negative controls the release gate
  runs. A change that touches a threat updates it in the same commit.
- [`tools/check/doc-refs.sh`](../tools/check/doc-refs.sh) checks that every file, anchor, `negative_*` test, C symbol,
  Kotlin member and Gradle task the documentation names exists; [`tools/check/links.sh`](../tools/check/links.sh)
  checks the relative links.

## 5. Integration and the local gate

Changes are developed on topic branches. Reviewed branches are merged into an integration branch, and the local gate
runs once on that branch; when it is green, the integration branch goes to `main`. Fixes for a maintenance line are
cherry-picked from `main` to `release/<X.Y>.x` ([release.md](release.md#releasing-from-a-maintenance-branch)).

The gate is [`tools/ci/local-matrix.sh`](../tools/ci/local-matrix.sh), run on the maintainer's Mac with Docker (Linux
and mingw), a running Android emulator and a Windows 11 VM. `tools/ci/local-matrix.sh --dry-run` lists its steps. By
default it has **66 steps**; a release needs `--with-interop --with-windows`, which makes **71** (and `--with-browser`
adds a Chrome WebTransport run, 72). Before step 1 it builds any missing OpenSSL and resolves every dependency, and it
refuses to start if either fails. What the steps cover:

| Area | Steps (names as the script prints them) |
|---|---|
| Lint and documentation | action and image pins, documentation references and their negative controls, the fuzz campaign script on stubs, the reliability report on fixtures, RFC table, links, guide samples, configuration tables, troubleshooting messages and `llms-full.txt` against the code (with their negative controls), HPACK tables and vectors, ktlint |
| Build integrity | dependency verification of every configuration, SPDX headers, module layers, ABI dumps, sans-IO architecture checks, shared source sets, the API reference and documentation site built with Dokka warnings as errors |
| JVM on macOS | every module's JVM tests, the coverage report (no threshold), the sample, the JNI library and its export whitelist, the Intel-Mac library |
| JVM on Linux | every module's JVM suite against the manylinux `libksl.so`, x64 and arm64, in Docker; the system-OpenSSL build mode |
| JVM on Windows | every module's JVM suite in the Windows 11 VM against the mingw-w64 dll (`--with-windows`) |
| Android | the AAR, its size gate, 16 KiB page alignment, R8 keep rules, the exports and OpenSSL of `libksl.so`, the device tests on the emulator (`androidConnectedCheck`), and the connection migration test against a server on the host (`androidMigrationDeviceTest`) |
| Native macOS and iOS | `macosArm64` tests, `iosSimulatorArm64` tests on the simulator, `iosArm64` compiled, OpenSSL symbol prefix |
| Native Linux | the `linuxX64` and `linuxArm64` test executables of every module, run in Docker; glibc floors; symbol prefix; the deployment guide's commands in a container (`tools/check/deployment-guide.sh`: `curl --http3-only` and `tcpdump` against the engine's Linux executable) |
| Native Windows | the `mingwX64` test executables are linked here, not run: they run in the hosted CI's `windows` job (stage 6) |
| C | the `ksl` C tests under ASan and UBSan on macOS; on Linux x64 and arm64 in Docker without sanitizers, with the ICMP error-queue tests required to have run |
| Fuzzing | the committed fuzz inputs of the Jazzer targets as regression tests |
| Simulation | `MonteCarloTest`: 200 seeded QUIC transfers through the network simulator on random links (delay, loss, reordering, MTU), each required to finish without violating the simulator's invariants |
| Performance | the allocation gate of `kuicksilver-bench` |
| Release checks | the negative controls of `tools/check/native-release.sh`, of `tools/release/local-release.sh` and of `tools/verify/verify-release.sh`; OpenSSL built without key logging |
| Reproducibility | `tools/check/double-build.sh macos-arm64`: OpenSSL, `libksl` and the JNI library built twice from two paths and compared |
| Interop | the JVM and Kotlin/Native interop images against quic-go, ngtcp2, quiche, picoquic, quinn and msquic in the QUIC Interop Runner, with the cells of [`tools/interop/required.json`](../tools/interop/required.json) required green (`--with-interop`; hours) |

Every run except a dry run writes a gate record, `build/ci/gate/<commit>.stamp`, with each step's result and
`result=pass` only when every step passed on a clean tree that stayed on the same commit. The release script accepts only
a passing record of the release commit run with `--with-interop --with-windows` and without `--skip-*` (stage 8).

Not covered by the local gate: running the `mingwX64` test executables and the Windows C tests (`ksl_test.exe`;
hosted CI only), the C tests under sanitizers
on Linux, and a physical iOS device ([ios.md, Device checklist](guide/ios.md#device-checklist)). Interop results and
their analysis are in [docs/spec/interop.md](spec/interop.md).

## 6. Hosted CI

[`.github/workflows/build.yml`](../.github/workflows/build.yml) is the CI counterpart of the local gate: the same step
names, and the same module and interop case lists from [`tools/ci/matrix.sh`](../tools/ci/matrix.sh). It runs on pushes
to `main` and `release/**`, on pull requests to them, weekly, and by hand. The QUIC Interop Runner jobs run only weekly
and by hand, so hosted CI does not repeat every local step on every push. Its jobs: `lint`; the OpenSSL
builds in Docker; `linux` (x64 and arm64: C tests, `libksl.so`, JVM suites, system OpenSSL); `linux-native` and
`linux-native-arm64` (Kotlin/Native test executables); `windows` (the `mingwX64` test executables and the C tests on a
Windows runner); `windows-jvm` (JVM suites on Windows against the mingw-w64 dll); `windows-loops-bench` (by hand only, with `only=windows-loops-bench`: `MultiLoopBenchmark` on Windows, not a gate); `openssl-next` (weekly, or by hand with `only=openssl-next`: the newest OpenSSL 4.x built on linux-x64 and macos-arm64 with the C tests and a JVM smoke test; `continue-on-error`, never required, no artifact); `apple` (ABI dumps, ASan C tests, JVM suites, the Intel-Mac library, the double build) and `apple-native` (`macosArm64`
and `iosSimulatorArm64` suites, `iosArm64` compiled); `android` (API 24 and 35 emulators); `jdk-compat`
(tests on JDK 17 and 25); `jvm-jar` and `consumer-smoke` (the jar with all five JNI libraries, a sample built from a
local publication); and, weekly or on request, the QUIC Interop Runner against the six peers. Nothing in it publishes,
signs or reads a secret, and pull requests from forks run with read-only rights; a maintainer approves the workflow
runs of every pull request from an outside contributor before they start (repository setting).

Hosted CI is not the release gate: a release needs the local gate record (stage 5). `main` has no branch protection
yet, so nothing requires a hosted run to be green before a change lands; the hosted results are read, not enforced. The other workflows:

- [`codeql.yml`](../.github/workflows/codeql.yml): CodeQL security queries over the C shim and the Kotlin JVM code, on
  pull requests and pushes to `main` and `release/**`, and weekly;
- [`scorecard.yml`](../.github/workflows/scorecard.yml): OpenSSF Scorecard, weekly and on pushes to `main`;
- [`perf.yml`](../.github/workflows/perf.yml): the interop runner's throughput measurements against the floors of
  `tools/interop/perf-thresholds.json`, by hand only (shared runners are too noisy for a weekly verdict; the workflow
  is disabled in the repository settings until the maintainer enables it again); the floors warn and do not fail yet;
- [`fuzz.yml`](../.github/workflows/fuzz.yml): a fuzzing campaign, one runner per target, weekly (2 hours per target)
  and by hand. A finding fails the job and notifies the maintainers; its reproducer and logs are never uploaded,
  because artifacts of a public repository are public and a finding stays private until it is fixed (that a target
  found something is visible in the public run, what it found is not);
- [`release.yml`](../.github/workflows/release.yml): a hosted release, not used ([release.md](release.md#alternative-the-release-workflow-not-used));
- [`interop-image.yml`](../.github/workflows/interop-image.yml): publishes the interop images of a released version to
  GHCR, by hand;
- [`cflite_pr.yml`](../.github/workflows/cflite_pr.yml): ClusterFuzzLite, prepared and kept off.

## 7. Before a release: soak, fuzzing, benchmarks

These run by hand on the maintainer's machine; each has a computed verdict, not a judgement.

- **Soak.** `kuicksilver-soak` runs the whole stack on real UDP for hours against a weighted mix of transfers, aborts,
  idle timeouts, stateless resets, migrations, 0-RTT, endpoint and client churn and Ktor requests, and samples memory,
  descriptors, threads, native objects and the library's own tables. A run passes when every series is flat after
  warm-up, every countable resource returns to its idle baseline after the load stops, and unexpected failures stay
  under 0.5% ([CONTRIBUTING.md, Tests](../CONTRIBUTING.md#tests), "Soak and churn"). Before a release: 24 to 72 hours.
  For 0.2.1 these were a 24-hour Kotlin/Native soak and a 37-hour JVM soak ([roadmap.md](roadmap.md)).
- **Fuzzing campaigns.** [`tools/fuzz/campaign.sh`](../tools/fuzz/campaign.sh) fuzzes every Jazzer target (TLS, QUIC,
  HTTP/3, QPACK, HTTP/2, HPACK, WebSocket, and stateful fuzzers of QUIC and HTTP/2 connections; `campaign.sh list`) and the libFuzzer harness of the `ksl` C parsing
  code, resumably and in slices, locally and in the weekly hosted run (stage 6); the grown corpora are minimized into
  `tools/fuzz/corpus/`, which the gate replays. A crash becomes a committed input, a unit test and a fix, and is
  handled as a private vulnerability report until it is fixed when it may be reachable by a peer. For 0.2.1: 2 hours per target.
- **Benchmarks.** [docs/benchmarks.md](benchmarks.md) compares goodput, CPU per GB and handshakes per second with
  quiche, quinn and msquic (`tools/bench/run-table.sh`), with its caveats: one Apple Silicon host, and the amd64 peer
  images run emulated. It is rerun for releases that change performance, not for every release.

## 8. The release

A release is built, checked, signed and uploaded from the maintainer's Mac by
[`tools/release/local-release.sh`](../tools/release/local-release.sh) ([release.md](release.md#every-release)). It refuses
a commit without a passing full gate record, a dirty tree, the wrong branch, a version already on Maven Central, a
`CHANGELOG.md` without the version and date, toolchains other than the pinned ones, and missing credentials; its
refusals have their own tests, run by the gate. It rebuilds all twelve OpenSSL targets from the signature-checked
tarball, checks every native library (architecture, exports, imports, OpenSSL version, no sanitizer or debug sections),
counts the deployment against the Central limits and uploads one signed deployment, which a maintainer publishes after
Central validates it.

- **Signatures.** Every artifact on Maven Central and the `v<version>` tag are signed with the release key
  (`22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68`).
- **SBOM.** A CycloneDX 1.6 SBOM of every publication, with the statically linked OpenSSL as a component, validated
  against the schema and attached, signed, to the GitHub release
  ([release.md, Supply chain](release.md#supply-chain-sbom-and-provenance)).
- **Provenance.** A signed in-toto statement with a SLSA provenance v1 predicate: the source commit, the toolchain and
  OpenSSL pins, the gate record and the digest of every uploaded file. This is SLSA Build Level 1: the same machine and
  person build, describe and sign, and no hosted build platform witnesses it ([release.md](release.md#build-provenance)).
- **Verification.** [`tools/verify/verify-release.sh`](../tools/verify/verify-release.sh) checks the tag, every
  signature, the SBOM and the provenance, and rebuilds the native libraries that are reproducible on a Mac, comparing
  them byte for byte with the published ones; the Linux and Windows JNI libraries, the `mingwx64` archives and the
  Kotlin and Gradle outputs (class files, klib IR) are not reproducible yet
  ([verifying.md](verifying.md#which-native-libraries-are-reproducible)).

## 9. After a release

[SECURITY.md](../SECURITY.md) is the process for vulnerabilities: private reports through GitHub, response and fix
targets, coordinated disclosure, GitHub Security Advisories, and the commitments for OpenSSL advisories that affect the
bundled OpenSSL (a patch release within 72 hours for Critical and High, within 7 days for other reachable issues). New
classes of bugs found after a release are added to the [Review checklist](../CONTRIBUTING.md#review-checklist).
