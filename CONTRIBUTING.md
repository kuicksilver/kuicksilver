<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Contributing to Kuicksilver

Thank you for helping. Kuicksilver is a network security component, so the bar for changes is high and the process is
explicit: an issue first for anything that changes behaviour or API, tests that fail before the fix, and a sign-off on
every commit. This document says how to build, test and propose changes. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md). Security issues go through [SECURITY.md](SECURITY.md), never a public issue.

## Building

### Prerequisites

| Tool | Needed for |
|---|---|
| JDK 21 | Gradle and the build (the toolchain is 21; JVM bytecode targets 17) |
| `curl`, `gpg`, `perl`, `shasum` | fetching and verifying the OpenSSL tarball, building OpenSSL |
| A C compiler (clang or gcc) | the `ksl` shim and its C tests |
| Docker (with `linux/amd64` and `linux/arm64`) | OpenSSL and `libksl` for Linux (manylinux2014, glibc 2.17) and Windows (mingw-w64), Linux test runs |
| Android SDK with NDK r28+ (r27 works: the scripts pass the 16 KiB page flags) | the Android AAR; set `ANDROID_NDK_ROOT` or let the scripts pick the newest NDK in the SDK |
| macOS with Xcode | Apple targets (cinterop needs a Mac host) |
| Python 3 | tools under `tools/` (symbol maps, QPACK tables, link and reference checks) |

The Gradle wrapper (`./gradlew`) downloads Gradle; Kotlin/Native downloads its toolchain into `~/.konan` on the first
native build. Please keep builds polite on shared machines: `--max-workers=2` is what the scripts use.

### OpenSSL

The project builds its own OpenSSL from a pinned release. `gradle/openssl.toml` holds the version, the tarball's
SHA-256 and the release signing key's fingerprint; `tools/openssl/fetch.sh` downloads the tarball and its signature,
checks the signature against the vendored key (`tools/openssl/openssl-release-key.asc`) and the SHA-256, and unpacks
it. `tools/openssl/build.sh <target>` builds a static OpenSSL with the flags in `tools/openssl/configure-flags.txt`;
Linux and mingw targets go through Docker (`tools/openssl/build-docker.sh`). On Kotlin/Native the OpenSSL symbols are
renamed with a `ksl_ossl_` prefix (`tools/prefix`, ADR-0007) so that another OpenSSL in the same binary cannot clash.

You rarely call these scripts by hand: the Gradle tasks (`opensslBuild<Target>`, `buildJniHost`, `buildAndroidJni`,
`buildKslA<Target>`) run them on demand. Outputs land in `build/openssl/<target>` and `build/openssl-prefixed/<target>`.
Never edit the pin without also updating the SHA-256 (and the key fingerprint if the signer changed), and never
disable the signature check.

### Dependency verification

Gradle checks every plugin and dependency it resolves against `gradle/verification-metadata.xml` (threat model 3.11): a
PGP signature by a key trusted for that publisher's group (the keys are in `gradle/verification-keyring.keys`, so no key
server is needed), or a SHA-256 for artifacts that are not signed or whose key no key server has. An artifact that
matches neither fails the build, the release included. When a dependency, a plugin or a toolchain pin changes (Renovate
pull requests too), update the file in the same pull request and review its diff:

```sh
# every configuration of every project and of build-logic, every test compilation, then the tasks that resolve detached
# configurations (ktlint, the ABI tools, Kover, Dokka, publishing)
./gradlew --max-workers=2 -I tools/check/resolve-all.init.gradle.kts --write-verification-metadata sha256,pgp --export-keys \
  -Pkuicksilver.openssl.prebuilt=true -Pkuicksilver.coverage -Pkuicksilver.sign=false -Dmaven.repo.local=/tmp/ksl-m2 \
  :build-logic:ksResolveAll ksResolveAll ksCompileAllTests assemble lintKotlin checkKotlinAbi checkInternalAbi \
  :kuicksilver-native:bundleAndroidMainAar :kuicksilver-native:koverXmlReportJvmTests publishToMavenLocal
```

`--write-verification-metadata` adds what the run resolved and keeps the rest; remove entries of versions no longer used.
The sample (`samples/realtime-telemetry`, its own build) links the same two files; after a change to its plugins run
`../../gradlew -I ../../tools/check/resolve-all.init.gradle.kts --write-verification-metadata sha256,pgp --export-keys
ksResolveAll jvmTest` there too (it replaces the keyring link with a copy: put the link back). Run the update with the
pins as they will be committed (an AGP or Kotlin pin that moves afterwards brings other tool artifacts), and check it
with the gate's step `check: dependency verification (every configuration)`:
`./gradlew --max-workers=2 -I tools/check/resolve-all.init.gradle.kts -Pkuicksilver.resolveAll.strict=true --continue
:build-logic:ksResolveAll ksResolveAll` resolves every configuration with verification on and fails on any gap.
Review new `<trusted-key>` entries (the key belongs to the group's publisher: compare its fingerprint with the one the
project publishes) and every new `<ignored-key>` (its artifacts then fall back to a checksum). Never set
`--dependency-verification lenient` or `off` in a script or a properties file. If a build fails with "Dependency
verification failed", do not regenerate blindly: find out why the artifact changed first. Gradle writes a report under
`build/reports/dependency-verification/`.

### Common commands

```sh
./gradlew --max-workers=2 :kuicksilver-quic:jvmTest              # one module's JVM tests (builds OpenSSL + libksl for the host first)
./gradlew --max-workers=2 :kuicksilver-quic:macosArm64Test       # the same on Kotlin/Native (macOS host)
bash tools/c-test.sh                                             # the ksl C tests under ASan/UBSan
./gradlew checkSpdxHeaders checkLayerDependencies                # headers and module layering
./gradlew :kuicksilver-quic:checkQuicArchitecture :kuicksilver-http3:checkHttp3Architecture   # sans-IO and import rules
./gradlew checkKotlinAbi                                         # public ABI against the dumps in <module>/api/
./gradlew updateKotlinAbi                                        # regenerate the dumps after an intended API change
bash tools/check/links.sh                                        # relative links in the Markdown files
bash tools/check/doc-refs.sh                                     # docs: paths, anchors, symbols; docs and comments: private markers
bash tools/check/rfc-table.sh                                    # the RFC compliance summary table: status, version, details link
tools/ci/local-matrix.sh --dry-run                               # list the gate's steps; drop --dry-run to run them
```

`checkKotlinAbi` over all modules covers every Kotlin/Native target, so it needs every OpenSSL build, including the
Docker ones. Linux JVM tests against the manylinux library run with `tools/ci/docker-jvm.sh linux-x86_64`. The QUIC
Interop Runner is driven by `tools/interop/build-image.sh` and `tools/interop/run-local.sh` (hours; needs the peers'
images). `KSL_INTEROP_TAG=<tag>` makes both use `kuicksilver-interop[-native]:<tag>` instead of `:local`, so a branch's
images can be built and run beside the ones of another checkout.

Throughput: `bash tools/interop/run-local.sh --perf` runs only the runner's `goodput` and `crosstraffic` measurements
(5 repetitions each, both roles) against the peers listed in `tools/interop/perf-thresholds.json`, then
`tools/interop/check-perf.sh` compares them with the floors there and exits 1 on a regression or on a cell (peer, role,
measurement) with no result; `--perf --results DIR` re-checks an earlier run. To move the floors after an intended change
(or a new peer), run `--perf` on a quiet host, review `bash tools/interop/check-perf.sh --update build/interop/<run> >
/tmp/t.json`, copy it over the thresholds file and update the "Measurements" line of `docs/spec/interop.md` in
the same commit. `bash tools/interop/check-perf-test.sh` runs the checker's exit-code cases on `tools/interop/testdata`.
The comparison with other stacks (goodput, CPU per GB, handshakes per second) is `tools/bench/run-table.sh`; its
method and the published numbers are in `docs/benchmarks.md`.

In the rebind cases `tools/interop/sim-entrypoint.sh` keeps the simulator's ready port closed until its first rebind is
over, so the client's handshake never runs across it: the `rebind-port` and `rebind-addr` cells no longer exercise a
rebind in the middle of the handshake. In `rebind-port` it opens the port 1.25 s after that rebind, so that every
transfer ends between the rebinds at 11 s and 16 s instead of on the one at 11 s: clients poll the port once a second,
so the start moves in whole seconds, and the 10 Mbit/s link, not the peer, sets how long the transfer takes. In
`rebind-addr` it opens it 0.3 s after, as in 0.2.0: the simulator's binding from 11 s on is always 193.167.0.155:745
(fixed seed), and ngtcp2's example server drops every datagram from a source port below 1024 (`prohibited_port()` in its
`examples/server.cc`, an anti-reflection filter), so the transfers there must end before it (the measurements are in the script; the poll phases were measured on an arm64
Docker Desktop host, where msquic, picoquic and quiche run emulated, and may differ on an amd64 host;
`KSL_INTEROP_START_GATE` overrides both). The handshake-time rebind is covered by `core.PathTest` (the
`rebindDuringHandshake` tests: `natRebindDuringHandshakeIsFollowedByTheServer`, `handshakeTimeRebind*`,
`handshakeTimeChallengeIsRepeatedUntilTheClientCanAnswer`, `unansweredHandshakeTimeChallengeDoesNotCloseTheConnection`
and their `negative_*` counterparts). A cell whose verdict rests on the environment is reported as `ENVIRONMENT` and
rerun, up to five times while the rerun hits the environment again (`tools/interop/environment.sh`; `--check-required`
counts a green rerun): a sim capture that was not flushed before teardown (not a cell the runner timed out: it cuts the
simulator's output off and fails the cell without reading a capture, so the timeout stands as the endpoints' verdict; a
host stall that times out a required cell is therefore a red to rerun by hand), and a rebind cell of our server failed
only because the client started just before the simulator's rebind at 1 s, so that nobody could decrypt the
PATH_CHALLENGE the runner checks when it went out (`tools/interop/handshake-challenge.py`), and a rebind cell whose
client's CONNECTION_CLOSE was the first packet from a new path (the rebind landed between the client's last packet and
its close), answered by the server with its own CONNECTION_CLOSE there as RFC 9000 section 10.2 allows, not a
PATH_CHALLENGE (`tools/interop/closing-rebind.py`; every earlier path must have passed the runner's check), and a rebind
cell whose client's last packets arrived from a new path after its CONNECTION_CLOSE had left, so that the server's
PATH_CHALLENGE there reached a client already closing (`tools/interop/closing-challenge.py`), and a cell
that ran on the simulator the timed-out cell before it left running (`Container sim Running` in its output: the runner's
`docker compose stop` after a timeout fails, and the reused simulator still sends to the previous server container's MAC;
`run-local.sh` has compose recreate the simulator in every cell, this rule is the backstop), and a cell whose server
container started only after the simulator had stopped waiting for it (`timeout occurred after waiting ... for
server:443` and no capture started: the scenario never ran and no endpoint sent a packet).
`bash tools/interop/environment-test.sh` runs those rules on `tools/interop/testdata`.

The floors were measured on a local host, so the thresholds file says `"blocking": false`: a cell below its floor is a
warning (exit 0) while a failed or missing cell still fails. To make the floors blocking, run `run-local.sh --perf` a
few times on quiet hosts, fold the runs in with `check-perf.sh --update <dir>[,<dir>...]` (it keeps the best mean per
cell), commit the new floors and set `"blocking": true` in the same commit. The weekly `perf` workflow
(`.github/workflows/perf.yml`) does the same on GitHub-hosted runners, but the GitHub Actions workflows are disabled;
the gate is `tools/ci/local-matrix.sh`.

## Style

- **EditorConfig.** `.editorconfig` is the formatting contract (UTF-8, LF, 4 spaces, 2 for YAML/TOML, 140 columns for
  Kotlin, `ktlint_official` code style). `./gradlew formatKotlin` rewrites, `lintKotlin` runs under `check`; the vendored
  Ktor contract tests keep upstream's style.
- **Explicit API.** Every module uses `explicitApi()`: public declarations carry a visibility modifier and a KDoc that
  states the contract (what it does, what it throws, which thread or coroutine context it expects). Internal helpers stay
  `internal`.
- **ABI dumps.** A change to the public API updates the dumps with `./gradlew updateKotlinAbi` in the same commit;
  reviewers read the `api/` diff. Declarations annotated `@InternalKuicksilverApi` are excluded from the dumps, with the
  companions and nested classes of an annotated top-level class; `checkInternalAbi` (part of `check`) verifies it.
- **Readability.** A human reviewer reads the code, not only a test runner: one statement per line (no `;` between
  statements, no `if (…) { a; b }` on one line), at most 140 columns, a comment says why and cites the RFC section or
  the decision, not what the next line does. Big files are split by responsibility, not by size.
- **SPDX headers.** Every source file starts with the two-line header, as a comment in the file's syntax:
  `Copyright 2026 The Kuicksilver Authors` and `SPDX-License-Identifier: Apache-2.0`. `checkSpdxHeaders` enforces it
  for Kotlin, Gradle scripts, C, shell, Python, cinterop `.def`, TOML, YAML and Dockerfiles; please add it to Markdown
  as well (JSON has no comments).
- **Layers and rules.** A module depends only on the layer directly below it (ADR-0005); the QUIC and HTTP/3 codecs are
  sans-IO (ADR-0004): no sockets, clocks, coroutines or default randomness in those packages. The checks above fail
  otherwise.
- **Commits.** `<type>(<scope>): <what>` on the first line (`feat`, `fix`, `test`, `docs`, `build`, `ci`, `refactor`,
  `chore`; scope is the module or area, for example `quic`, `tls`, `http3`, `ksl`), then a body that says why.
- **Documentation.** The code blocks of `docs/guide/tls.md`, `docs/guide/quic.md`, `docs/guide/http3.md` and
  `docs/guide/ktor.md` are compiled and run by `GuideSamplesTest` (marked `// guide:<module>:<name>`); change both
  together. Behaviour that touches an RFC or a
  threat updates `docs/spec/rfc-compliance.md` (the summary row and its details in `docs/spec/rfc/<rfc>.md`) or
  `docs/spec/threat-model.md` in the same pull request.

## Tests

- **Test first.** A bug fix starts with a test that fails for the reason in the issue (RED), then the fix makes it pass
  (GREEN). Say in the pull request which test went red.
- **Negative controls.** Every security check has a test that must fail when the check is removed. Such tests are named
  `negative_<what>` and are listed in the threat model; keep the names stable.
- **Determinism, no sleeps.** Do not wait with `sleep` or `delay` for something to happen. Use virtual time
  (`kotlinx-coroutines-test`, the sans-IO core takes time as a parameter), the network simulator in
  `kuicksilver-testing` (seeded and reproducible), `MemoryNetwork` for in-memory UDP, or wait for an explicit event with
  a generous timeout. A test that is flaky is a bug; report the seed.
- **Platforms.** Common behaviour is tested in `commonTest` so it runs on the JVM, Android and Native. Tests that need a
  Linux-only facility (GSO/GRO, `SO_REUSEPORT` flow hashing) skip themselves elsewhere and run in the Docker steps; the
  accelerated UDP socket itself also runs on macOS and Windows (Windows tests need a Windows host or VM:
  `tools/ci/local-matrix.sh --with-windows`).
- **Coverage.** `./gradlew --max-workers=2 -Pkuicksilver.coverage :koverHtmlReportJvmTests` runs the JVM tests of the
  published modules under Kover and merges their line and branch coverage into `build/reports/kover/htmlJvmTests/index.html`.
  `:koverXmlReportJvmTests` writes the same data as XML to `build/reports/kover/reportJvmTests.xml`, and
  `:<module>:koverHtmlReportJvmTests` reports one module. Only the JVM target is measured: Android host tests cannot load
  the JNI library, and Kover does not instrument Kotlin/Native. The generated QPACK tables are excluded. The report has
  no threshold, by decision; use it to find untested code, not as a gate. Without `-Pkuicksilver.coverage` the Kover
  agent is off for every test task, so ordinary test runs are not instrumented; the report tasks need the property.
- **Soak and churn.** `kuicksilver-soak` runs the whole stack on real UDP for a set time: a Ktor server (HTTP/1.1 and
  HTTP/3 on one port) and raw QUIC servers, against client coroutines doing a weighted mix of transfers (1 KiB–4 MiB),
  aborted streams, idle timeouts, stateless resets, migrations, 0-RTT resumptions, endpoint and `HttpClient` churn,
  refusals at a full accept queue and Ktor requests over both protocols. It samples RSS, heap after GC, direct buffers,
  descriptors, threads, the `ksl` live-object counters and the library's own tables (connections, connection IDs,
  per-IP and per-remote maps, timer heap, queues, replay register, session caches, client pools, server handlers).
  It is not part of `check`:

  ```sh
  ./gradlew --max-workers=2 :kuicksilver-soak:jvmTest -Pkuicksilver.soak.minutes=30          # JVM
  ./gradlew --max-workers=2 :kuicksilver-soak:macosArm64Test -Pkuicksilver.soak.minutes=30   # Kotlin/Native, macOS
  ./gradlew --max-workers=2 :kuicksilver-soak:linkDebugTestLinuxArm64                        # then, in a container:
  docker run --rm -v "$PWD/kuicksilver-soak/build:/b" -e KSL_SOAK_MINUTES=30 -e KSL_SOAK_REPORT=/b/soak ubuntu:24.04 /b/bin/linuxArm64/debugTest/test.kexe
  ```

  Options: `-Pkuicksilver.soak.clients=8`, `.rate=40` (iterations per second, a ceiling), `.sampleSeconds=15`,
  `.warmupMinutes` (default a fifth of the run, at least 2), `.label`, `.report=<dir>` (default
  `kuicksilver-soak/build/soak`), `.scenarios=KtorH3,KtorAbort` (only these scenarios of the mix, each with its weight),
  `.qlog=<dir>` (every Ktor HTTP/3 connection keeps its last qlog records in memory; one that ends by a timeout or an
  internal failure is written to `<dir>` with its peer's trace); the container takes the same as `KSL_SOAK_*` variables.
  Each unexpected failure is printed with its time and scenario. A run **passes** when, after
  warm-up, every sampled series is flat — its Theil–Sen slope (the median of all pairwise slopes, robust to GC
  saw-teeth and in-flight bursts; beyond 2,048 samples the median of 2²¹ pairs drawn from a fixed seed, so a 72-hour or
  7-day run at the default rate is judged in 16 MiB and well under a second per series) times the window stays within `max(absolute, relative × median)` (32 MiB / 10% for RSS,
  16 MiB / 10% for heap, 8 / 10% for descriptors and threads, 5 / 25% for counts) — every countable resource (`ksl`
  objects, connections, CIDs, maps, timers, queues, handler coroutines, descriptors within 4) is back at its idle
  baseline within 90 s after the load stops, and unexpected failures stay under 0.5% of iterations. The report
  (`<label>.md`, `<label>.csv`) lists every series. When it reports a leak, `-Pkuicksilver.soak.attribute=20` runs each
  scenario alone (`.scenarios=QuicMigration,KtorH3` for some only) and prints what it left behind. On Kotlin/Native
  `kn.heapAfterGcKiB` counts the default allocator's pages (128 KiB steps), not live objects, so it includes fragmentation;
  link with `-Pkuicksilver.soak.allocator=std` (with `linkDebugTest…` for a container) to measure exact live bytes. The
  report also lists RSS and heap at idle before and after the load. Run it on an otherwise
  idle machine: a starved process misses the scenarios' timeouts (a 1 s idle timeout checked within 10 s) and fails on
  unexpected failures, not on resources. Before a beta: 2 h nightly; before a release: 24–72 h.
- **Fuzzing.** Jazzer targets live in `kuicksilver-tls`, `kuicksilver-quic` and `kuicksilver-http3` under
  `src/jvmTest/.../fuzz` (among them `ConnectionFuzzTest`, a stateful fuzzer of a client/server `ConnectionCore` pair, and
  the 0-RTT targets); `tools/fuzz/ksl/` holds the libFuzzer harness of the `ksl` parsing code. Their committed inputs run
  as regression tests in `jvmTest`. `tools/fuzz/gen-seeds.sh` regenerates the seed corpora, `tools/fuzz/ksl/build.sh
  --seeds` the ksl seeds. Long runs use `tools/fuzz/campaign.sh`: it fuzzes
  every target in slices of at most 20 minutes at background priority (`taskpolicy -b`, `nice 19`, one thread), pauses
  between slices, resumes where it stopped (state in `build/fuzz-campaign/`) and gives each slice to the target with the
  least time so far. `tools/fuzz/campaign.sh status` prints hours, executions and coverage per target;
  `tools/fuzz/campaign.sh minimize` merges the grown corpora into `tools/fuzz/corpus/<target>/`, which is committed and
  seeds later campaigns; `tools/fuzz/campaign.sh prune` instead reduces each grown corpus in place to the inputs that add
  coverage beyond that committed corpus and the seeds. Options: `--slice MIN`, `--goal HOURS` per target, `--goals id=HOURS,...` per target, `--hours
  HOURS` of wall clock, `--jobs N` slices at once (each on its own target, default 1), `--nice N` (default 19),
  `--targets id,...` (`tools/fuzz/campaign.sh list`), `--fork N` (libFuzzer/Jazzer fork mode, N workers on the slice's
  target; default off, for a machine the campaign owns). On GitHub, *Actions → fuzz → Run workflow* (`.github/workflows/fuzz.yml`,
  dispatch only) gives every target its own runner for `hours_per_target` (`--fork` with one worker per CPU, `--nice 0`,
  `--gap 0`), keeps each grown corpus, pruned, in the Actions cache between runs (one entry per target and branch: the
  `corpus-cache` job deletes the older ones), fails the target's job on a finding and uploads
  its reproducers, logs and `stats.tsv` as `fuzz-<target>`; the run summary is the `status` table. A crash you find becomes a `crash-*` input next to the seeds, a unit test that
  reproduces it and a fix; delete `build/fuzz-campaign/crashed-<target>` so the campaign takes the target again. A timeout
  is replayed first: one whose input runs in time alone (a slice starved on a busy machine) is recorded as `load-timeout`
  in `build/fuzz-campaign/load-timeouts/` and is not a finding. ClusterFuzzLite is not used: `.clusterfuzzlite/` and
  `.github/workflows/cflite_pr.yml` are a setup that was prepared but never run, kept disabled, and they cover fewer
  targets than the campaigns.

## Proposing a change

1. **Open an issue first** for anything beyond a small fix: new API, changed behaviour, a new dependency, a new
   platform. Describe the use case before the API.
2. **New public API** starts as `@ExperimentalKuicksilverApi`; it becomes stable after it has been used, in a later
   minor release. API that can break security guarantees when misused (custom verifiers, key logging) is
   `@DelicateKuicksilverApi`. Deprecations go warning, then error, then removal, with at least one minor release between
   steps.
3. **Keep pull requests focused**: one concern per pull request, one logical change per commit.
4. Add an entry to [CHANGELOG.md](CHANGELOG.md) under `Unreleased` for any user-visible change.

## Developer Certificate of Origin

Every commit must be signed off: `git commit -s` adds
`Signed-off-by: Your Name <you@example.com>`, which certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
— that you wrote the change or otherwise have the right to submit it under the project's license. Use your real name or
the name you are publicly known by. Only a human signs off; a tool never adds `Signed-off-by` on your behalf. A pull
request with an unsigned commit cannot be merged (`git commit --amend -s` or `git rebase --signoff` fixes it).

## AI assistance

The maintainers use AI coding tools in this project, and contributors may too, under these rules:

- **You understand every line you submit and you are responsible for it**, exactly as if you had typed it. "The tool
  wrote it" is not an answer in review. Be ready to explain any part of the change.
- **Disclose it.** If an AI tool generated a meaningful part of a commit, add a trailer naming the tool (and model when
  you know it): `Assisted-by: <tool>[:<model>]`, for example `Assisted-by: Claude Code`. Do not use `Co-authored-by:`
  for a tool. `Signed-off-by:` is yours alone.
- **Write issues and review comments in your own words.** Summaries are fine; walls of generated text are not.
- **Never paste non-public vulnerability details** (reports, exploits, embargoed advisories) into third-party AI
  services.
- Generated tests must still fail without the fix; generated documentation must match the code.

## Pull request checklist

- [ ] An issue exists for non-trivial changes and is linked.
- [ ] Every commit is signed off (`git commit -s`); AI help is disclosed with `Assisted-by:`.
- [ ] Tests: a test failed before the change and passes after it; new security checks have a `negative_*` control.
- [ ] `checkSpdxHeaders`, `checkLayerDependencies`, the architecture checks and the affected module tests pass locally.
- [ ] Public API: KDoc written, `./gradlew updateKotlinAbi` run and the `api/` diff reviewed; new API is
      `@ExperimentalKuicksilverApi`.
- [ ] Docs: guides, `docs/spec/rfc-compliance.md` (with `docs/spec/rfc/`) or `docs/spec/threat-model.md` updated where
      behaviour changed; `tools/check/links.sh`, `tools/check/doc-refs.sh` and `tools/check/rfc-table.sh` pass.
- [ ] `CHANGELOG.md` has an `Unreleased` entry for user-visible changes.

## Review checklist

Reviewers (and authors, before asking for review) check every change against the classes of bugs this project has
already shipped or nearly shipped. Each line names the question to ask of the diff.

- **A deadline on every wait on a peer.** Handshakes, request heads, bodies, writes to a slow reader, graceful
  shutdown: what ends the wait if the peer goes silent or trickles one byte at a time? Deadlines that measure
  progress, not a fixed total, so a slow but live peer is not cut off.
- **Backoff on every error-retry loop.** An `accept()` that fails with `EMFILE`, a read that keeps failing: does the
  loop sleep, grow the delay and rate-limit its log, or does it spin a core?
- **Bounded memory and CPU per peer and per run length.** Header and body limits, queue sizes, per-connection state;
  and no work that grows with how long the process has run (a soak verdict that was quadratic in samples).
- **Every resource closed on every path.** Sockets, file descriptors and TLS state on success, failure, cancellation
  and timeout, including when another coroutine already ended the writer or reader.
- **One reader and one writer per stream.** No path that lets two coroutines read the same input concurrently.
- **Connection-reuse promises kept.** A response that leaves request bytes unread, a body still incomplete when the
  head goes out, an unanswered `Expect: 100-continue`: the connection is drained within a limit or closed
  (`Connection: close` and a short linger, so the peer sees a response, not a reset).
- **Retries only where they are safe.** A timeout or failure on a pooled connection is not retried unless the request
  is replayable and the failure proves the request was not processed.
- **No silent fallbacks.** When a mode cannot be honoured (`H3Only` with a proxy or an `http://` URL), the call fails
  with a clear error instead of quietly using another protocol. Fallbacks that are intended are visible to the caller.
- **Errors say what happened and leak nothing.** Status codes match the cause (a body timeout is 408, not a
  relabelled 500), and response bodies carry no internal messages.
- **Documentation claims verified against the code.** Every "the engine does X" in a guide, KDoc or CHANGELOG has a
  test or a line of code behind it; nothing points at files or features that do not exist.
- **A failed channel is not an end.** ktor's `readAvailable` returns -1 and `copyTo` (the limited form too) returns
  normally for a channel closed with a cause, as for one closed cleanly, whenever the cause is already set when they
  look: after the loop or the -1, check `closedCause`, or a reset passes for a complete body (a cut response, a request
  body sent with its last chunk, `close_notify` after a failed stream).
- **Tests that are not flaky by construction.** Ports for TCP and UDP pairs are reserved together, timing budgets
  leave room for a loaded host, and negative tests own every address they assert nothing answers on. No test waits
  for something the protocol allows never to happen (a request stream reset before its HEADERS were read surfaces no
  request), and every wait has a deadline that fails with a message naming what did not happen.
- **No pipe into `grep -q` under `pipefail`.** `grep -q` exits at its first match; a writer still writing then dies
  of SIGPIPE and pipefail turns the match into a failure, and a writer that exits non-zero makes the test false
  whatever it printed. Gate scripts read the output into a variable first and grep that (`grep -q x <<< "$out"`).

New classes of bugs found in review or after a release are added to this list.
