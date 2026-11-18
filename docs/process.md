<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# How a change is checked

What every change goes through before it reaches a release, and what happens after. Each stage names the script or
document that implements it, so every statement here can be checked against the repository. Where a stage is a
practice that no tool enforces, or is partial, this page says so.

| Stage | What | Where | Enforced by a tool |
|---|---|---|---|
| [1](#1-a-test-that-fails-before-the-fix) | A test that fails before the fix | [CONTRIBUTING.md, Tests](../CONTRIBUTING.md#tests) | partly: that every test can run, the test count per source set and the sleeps in tests are checked ([repository checks](#repository-checks)); that the test failed before the fix is not |
| [2](#2-review-the-code-and-the-rfc-text) | Code review and a check against the RFC text | [CONTRIBUTING.md, Review checklist](../CONTRIBUTING.md#review-checklist) | no |
| [3](#3-where-the-rfc-leaves-a-choice-reference-stacks) | Comparison with reference stacks where the RFC leaves a choice | `docs/spec/rfc/<rfc>.md`, peer notes; commit messages | no |
| [4](#4-the-rfc-compliance-matrix-and-the-threat-model) | The RFC compliance matrix and the threat model | [rfc-compliance.md](spec/rfc-compliance.md), [threat-model.md](spec/threat-model.md) | format, references and the tests named behind a ✅: yes; content: review |
| [5](#5-integration-and-the-local-gate) | Integration branch and the local gate on every target | [`tools/ci/local-matrix.sh`](../tools/ci/local-matrix.sh) | yes |
| [6](#6-hosted-ci) | Hosted CI on pushes and pull requests to `main` and `release/**` | [`.github/workflows/build.yml`](../.github/workflows/build.yml) | runs automatically; no rule requires it green yet (the branch ruleset blocks deletion and force pushes only) |
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
the tests that still wait with a delay. The sleeps that remain may only become fewer, and a test that no runner would
run, or a drop in the number of tests, fails the gate ([repository checks](#repository-checks)).

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
and there is no second maintainer: roles, decisions and the access continuity plan are in
[GOVERNANCE.md](../GOVERNANCE.md). `.github/CODEOWNERS` names the maintainer for every path.

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
  and its details in the same commit. [`tools/check/rfc-table.sh`](../tools/check/rfc-table.sh) (negative controls in `rfc-table-test.sh`) checks the table format
  and that every details link and anchor exists; [`tools/check/rfc-tests.py`](../tools/check/rfc-tests.py) that every
  test a ✅ section names exists and that a ✅ section names one ([repository checks](#repository-checks)); whether the
  tests pin what the row claims is a matter of review (stage 2).
- [docs/spec/threat-model.md](spec/threat-model.md) lists the assets, attackers, threats and mitigations, and in
  [section 5](spec/threat-model.md#5-negative-controls--release-gate-checklist) the negative controls the release gate
  runs. A change that touches a threat updates it in the same commit.
- [`tools/check/doc-refs.sh`](../tools/check/doc-refs.sh) checks that every file, anchor, `negative_*` test, C symbol,
  Kotlin member and Gradle task the documentation names exists; [`tools/check/code-refs.py`](../tools/check/code-refs.py)
  that every source line `docs/spec` cites (`File.kt:N`) is still the line recorded in `tools/check/code-refs.lock`;
  [`tools/check/links.sh`](../tools/check/links.sh) checks the relative links.

## 5. Integration and the local gate

Changes are developed on topic branches. Reviewed branches are merged into an integration branch, and the local gate
runs once on that branch; when it is green, the integration branch goes to `main`. Fixes for a maintenance line are
cherry-picked from `main` to `release/<X.Y>.x` ([release.md](release.md#releasing-from-a-maintenance-branch)).

The gate is [`tools/ci/local-matrix.sh`](../tools/ci/local-matrix.sh), run on the maintainer's Mac with Docker (Linux
and mingw), a running Android emulator and a Windows 11 VM. `tools/ci/local-matrix.sh --dry-run` lists its steps. By
default it has **71 steps**; a release needs `--with-interop --with-windows`, which makes **76** (and `--with-browser`
adds a Chrome WebTransport run, 77). Before step 1 it builds any missing OpenSSL and resolves every dependency, and it
refuses to start if either fails. What the steps cover:

| Area | Steps (names as the script prints them) |
|---|---|
| Lint and documentation | action and image pins, documentation references, the [repository checks](#repository-checks) (tests that cannot run, the test-count floor, sleeps in tests, name-service calls in library code, the tests behind ✅ rows, the commit types of the branch) and their negative controls, the fuzz campaign script on stubs, the reliability report on fixtures, RFC table, links, guide samples (with their negative controls), configuration tables, troubleshooting messages and `llms-full.txt` against the code (with their negative controls), HPACK tables and vectors, ktlint |
| Build integrity | dependency verification of every configuration, SPDX headers, module layers, ABI dumps, sans-IO architecture checks, shared source sets, the API reference and documentation site built with Dokka warnings as errors |
| JVM on macOS | every module's JVM tests, the coverage report (no threshold), the engine interop bench (the Ktor client and server engines against Ktor's Netty and CIO engines, OkHttp, the JDK's HttpClient and Netty's HTTP/2 and HTTP/3 codecs; [interop.md](spec/interop.md#engine-interop-the-ktor-engines-against-other-http-stacks-jvm-2026-11-13)), the samples (`realtime-telemetry`; the Compose demo's build, its iOS framework and its tests), the JNI library and its export whitelist, the Intel-Mac library |
| JVM on Linux | every module's JVM suite against the manylinux `libksl.so`, x64 and arm64, in Docker; the system-OpenSSL build mode |
| JVM on Windows | every module's JVM suite in the Windows 11 VM against the mingw-w64 dll (`--with-windows`) |
| Android | the AAR, its size gate, 16 KiB page alignment, R8 keep rules, the exports and OpenSSL of `libksl.so`, the device tests on the emulator (`androidConnectedCheck`), and the connection migration tests against a server on the host (`androidMigrationDeviceTest`, and the Compose demo's `migrationDemoDeviceTest`) |
| Native macOS and iOS | `macosArm64` tests, `iosSimulatorArm64` tests on the simulator, `iosArm64` compiled, OpenSSL symbol prefix |
| Native Linux | the `linuxX64` and `linuxArm64` test executables of every module, run in Docker; glibc floors; symbol prefix; the deployment guide's commands in a container (`tools/check/deployment-guide.sh`: `curl --http3-only` and `tcpdump` against the engine's Linux executable) |
| Native Windows | the `mingwX64` test executables are linked here, not run: they run in the hosted CI's `windows` job (stage 6) |
| C | the `ksl` C tests under ASan and UBSan on macOS; on Linux x64 and arm64 in Docker without sanitizers, with the ICMP error-queue tests required to have run |
| Fuzzing | the committed fuzz inputs of the Jazzer targets as regression tests |
| Simulation | `MonteCarloTest`: 200 seeded QUIC transfers through the network simulator on random links (delay, loss, reordering, MTU), each required to finish without violating the simulator's invariants |
| Performance | the allocation gate of `kuicksilver-bench` |
| Release checks | the negative controls of `tools/check/native-release.sh`, of `tools/check/build-paths.py` (no home-directory path in an artifact), of `tools/release/local-release.sh` and of `tools/verify/verify-release.sh`; the refusals of the gate's own step selection (`tools/ci/local-matrix-test.sh`); OpenSSL built without key logging |
| Reproducibility | `tools/check/double-build.sh macos-arm64`: OpenSSL, `libksl` and the JNI library built twice from two paths and compared; `tools/check/native-flags-test.sh`: a builder's `CC`, `CPPFLAGS`, `CFLAGS` and `LDFLAGS` are added after the project's flags and never reach a release or the double build ([building.md](guide/building.md#your-compiler-and-flags)) |
| Interop | the JVM and Kotlin/Native interop images against quic-go, ngtcp2, quiche, picoquic, quinn and msquic in the QUIC Interop Runner, with the cells of [`tools/interop/required.json`](../tools/interop/required.json) required green (`--with-interop`; hours) |

A full run (not a dry run) writes a gate record, `build/ci/gate/<commit>.stamp`, with `selection=all`, each step's
result and `result=pass` only when every step passed on a clean tree that stayed on the same commit. The release script
accepts only a passing record of the release commit that ran every step, with `--with-interop --with-windows` and without
`--skip-*` (stage 8).

After a fix, some steps can be run again without the whole gate: `--only 25,48-49,52` runs the listed steps (numbers
and ranges), `--from 44` runs step 44 and every later one. The numbers are those of a full run with the same
`--skip-*` and `--with-*` options, as `--dry-run` with those options lists them and as a failure line (`[25] ...`,
`build/ci/25.log`) shows them; the steps left out print nothing. Such a run is never a gate: it does not write or change
the stamp, but `build/ci/gate/<commit>.partial`, with the selection and `result=partial-pass` or `partial-fail`, and the
release script and the reliability report refuse it. Before anything runs, the script refuses an unknown or malformed
step number, a number past the last step, an empty list, `--only` together with `--from`, and a selection that leaves
out a step whose output a selected step reads (the AAR for the Android checks, the linked Linux test executables, the
interop images, the Linux C test runs for the ICMP check); it names the steps to add. The preflight builds only the
OpenSSL targets (and their build images) that the selected steps read or run in, and resolves the dependencies only
for the Docker JVM steps. Steps that check what an earlier part of the gate
built (the JNI library's exports, the prefixed OpenSSL archives, the Windows dll, the Linux libraries in the JVM
interop image) build it themselves, or rebuild it when it is not from this run, so a selection never checks a
leftover of an earlier build.

### Repository checks

Bug classes that came back after review are checked by scripts under `tools/check/`, each with negative controls on a
scratch repository (`<name>-test.sh`), in step 3 of the local gate (step 4 runs the negative controls) and in the hosted
CI's lint job; `test-bytecode.py` reads compiled classes, so it runs in the gate's JVM test step (which also compiles the
Android host and device tests) and after the sample builds, after the JVM tests and the realtime-telemetry sample of the
CI `apple` job and on the Android host and device tests in the CI `android` job. Each takes a few seconds at most. Where a check keeps a lock file, the lock changes in the same
commit as the code it records, so the change is in the diff a reviewer reads.

| Check | Fails on | Lock or allowlist |
|---|---|---|
| [`test-discovery.py`](../tools/check/test-discovery.py) | a `@Test` (also imported under another name) that no runner runs: declared inside a function body or lambda, at top level, in an object, companion object, object expression, interface or enum class, in an inner or private class, private, with parameters, returning a value by its source (a declared return type, `= 42`, `= assertFailsWith<E> { }`), in a class whose constructor needs an argument, in an abstract or sealed class nothing extends, in a main source set, or in a source set no build script compiles | none: such a test is fixed |
| [`test-bytecode.py`](../tools/check/test-bytecode.py) | in the compiled JVM, Android host and Android device test classes (`build/classes/kotlin/jvm/test`, `build/classes/kotlin/android/hostTest`, `build/classes/kotlin/android/deviceTest`; a module with such tests and no class directory fails) and, with `--targets samples`, the samples' test classes: a test method whose descriptor returns a value (JUnit 5 skips it without a word: `= runBlocking { 1 }`), a static or private one (a test in a top-level function or a local one), one with parameters, a JUnit 4 one that is not public or in a class that is not public, an abstract one, an override of a test without the annotation, one in a local, anonymous or private nested class, one whose class has no non-private constructor without parameters (an object, a companion object, an inner class), or one in an abstract class nothing extends | none |
| [`test-count.py`](../tools/check/test-count.py) | a test (`@Test` or `@FuzzTest`; an `@Ignore`'d or `@Disabled` one does not count) listed in `tools/check/test-count.lock` that is gone, named in the finding, or a test the lock does not list | `--update` rewrites the lock, one sorted line per test; commit it with the change |
| [`test-sleeps.py`](../tools/check/test-sleeps.py) | more sleeps in a test file than `tools/check/test-sleeps.lock` records (a new file: none), unless Git (`git diff -M -C` from the merge base with `main`) takes the file for a rename or copy of a locked file of the same source set that has as many fewer: a rename, move or split, which `--update` carries; sleeps removed in one file never pay for new ones in another; or fewer sleeps than the lock, until it is lowered. Sleeps are calls of `delay`, `sleep` (`Thread.sleep`), `usleep`, `nanosleep`, `Sleep`, `parkNanos` and `parkUntil`, also under an import alias, as a reference (`Thread::sleep`) or in a string template, and calls of the test sources' polling helpers whose body sleeps (`eventually { }`), a call resolved as Kotlin sees the name (the file's own function first; a private or local one nowhere else; another file's only in the same package or imported) | `--update` lowers the lock and carries moves; a new file that needs a real wait is named in `tools/check/test-sleeps.allow` with its reason |
| [`env-apis.py`](../tools/check/env-apis.py) | a host-name lookup in the main Kotlin, Java and C sources of the library modules, also in a string template or as a reference: Ktor's `hostname`, java.net's `hostName` / `getHostName` / `canonicalHostName`, `InetAddress.getLocalHost`, and `gethostname`, `getnameinfo`, `gethostbyaddr`, `GetNameInfoW`, `NSHost` | a use that does no lookup is counted per file in `tools/check/env-apis.allow`, `<path> \| <api> \| <count> \| <reason>`: one use more fails |
| [`rfc-tests.py`](../tools/check/rfc-tests.py) | a test or test class named in a ✅ section of `docs/spec/rfc/*.md` that does not exist (`Class.test`, `Class#test`, a `.test` of the class named before it, a bare name in a list of tests that is no test and no name of the sources, a class name close to a test class's but in no source), a ✅ section that names no test, a ✅ summary row whose details section is not ✅ | `tools/check/rfc-tests.lock` lists the ✅ sections without a test when the check came; it only shrinks (`--update`) |
| [`reproducers.py`](../tools/check/reproducers.py) | a file named like a fuzzing artifact (`crash-`, `timeout-`, `oom-`, `leak-`, `slow-unit-`, `minimized-from-`, also with `_` and in any case, so Jazzer's `Crash_<hash>.java` too), tracked or not, anywhere in the tree, without an entry in `tools/fuzz/reproducers.txt`; an entry whose input is gone (renamed or deleted), a link, or no regression or corpus input of a Jazzer target or of the ksl harness (`tools/fuzz/corpus/ksl.parsers`, which the verifier replays through `tools/fuzz/ksl/build.sh`); an unknown state (`live`: the input fails again with the plant; `dead`: it passes even then), a fix that is no commit or (with the history) changed none of the source files its plant changes (documents do not count), a fix commit that added no line its plant removes (compared without comments and spacing: a plant takes back the code of its fix as it is now, so a fix rewritten later is named with the rewrite's commit; a commit that only changed the same file is marked `<hash>~file` and needs a matching one beside it), a plant that changes a file no fix commit changed (a harness made to throw the expected failure), a dead entry without a guard test, a guard test that `tools/check/test-count.lock` does not list, that the JVM tests do not run or that belongs to another module, a live entry without the piece of its failure; a plant (`tools/fuzz/plants/<name>.patch`) that is missing, does not apply to the tree (`git apply --check`), changes nothing, touches an input, a document, the tooling or a guard test's own file, or that no entry uses | the entries themselves; `tools/fuzz/reproducers-verify.sh` checks what they claim |
| [`fuzz-formats.py`](../tools/check/fuzz-formats.py) | for the committed fuzz inputs (`tools/fuzz/corpus/<target>/` and the regression inputs `<Class>Inputs/<method>/`) of a target whose program traces the operations it decodes (`FuzzTrace` in the fuzz packages' `FuzzCase.kt`): a jvm target of `tools/fuzz/campaign.sh` with neither a lock `tools/fuzz/formats/<target>.lock` nor a reason in `tools/fuzz/formats/untraced.txt`, or with both; a lock line that is malformed, unsorted, of no input of its target, of an input that is gone or whose bytes changed, and an input the lock does not list; and, against the merge base with `main`, a recorded input that no longer decodes as recorded there (found by its bytes, so a rename keeps it, or by its path, so a rewrite that keeps its operations does) without a line naming its target added to `tools/fuzz/formats/changes.txt` on the branch; and in `tools/fuzz/formats/flags.txt`, which names every flag bit, setup bit and outcome of the traced connection programs by its constant and its trace name: a malformed row, a trace name that is not its constant's in lowerCamelCase, a value, constant or trace name listed twice, bits that are not 1, 2, 4, ... or outcomes not 0, 1, 2, ... without a gap, a row whose constant is missing or has another value in the program's source or whose name is not the one the program's name table gives, a name of that table no row lists, a constant the program's KDoc does not name, and, against the merge base, a row changed or removed (a renamed or moved flag) without a line in `changes.txt` naming every target of its program. Whether each input still decodes as its lock says is checked by `CommittedCorpusReplayTest` in the JVM tests, which runs every committed input | `KUICKSILVER_FUZZ_FORMATS=record` with the modules' JVM tests writes the locks; a changed decoding needs its reason in `changes.txt` |
| [`commit-msg.sh`](../tools/check/commit-msg.sh) | a commit subject without a conventional type: `type(scope): subject` or `type: subject`, the type one of `fix`, `feat`, `test`, `docs`, `build`, `ci`, `refactor`, `perf`, `bench`, `chore`, `revert` (Git's `Revert "..."` passes too; the gate checks every commit of `main..HEAD` but merges, and a range end that is no commit is an error); a commit hash the message cites that is not in the history of the branch (`HEAD` for the hook): one from before a rebase or another branch's (rule below) | none |
| [`deadline-sites.py`](../tools/check/deadline-sites.py) | a deadline in a main source set without a verdict: a call or reference of kotlinx.coroutines' `withTimeout` or `withTimeoutOrNull` (by its import, an import alias, a star import or the qualified name), a select `onTimeout` clause, a `launch`/`async` timer that begins with `delay(...)` or cancels after it, a `select` that cancels; one site more in a function than its entry judges; an entry for a site that is gone. The verdict answers what happens when the deadline fires as the work returns: `pure-wait`, `completedWithin` (the result is kept once the block returned), `made-flag`, `side-effect-free` or `select-atomic`; a site whose caller acts on a result the deadline can drop has no verdict and is fixed | `tools/check/deadline-sites.allow`, `<path> \| <function> \| <form> \| <count> \| <verdict> \| <reason>` |
| [`test-hooks.py`](../tools/check/test-hooks.py) | a test that sets a global test hook (a `var <name>ForTest` at top level, in an object or a companion object, or a `set...ForTest(x)` function there) and does not put it back to its initial value in a `finally` after the set or in `@AfterTest` (`@After`, `@AfterEach`, `@AfterClass`, `@AfterAll`) of its class; a global hook without an initial value | none: the test resets it, or the hook becomes per instance |
| [`tracked-hashes.py`](../tools/check/tracked-hashes.py) | in every tracked text file, a commit hash by the rule of `commit-msg.sh` above (the two scans are checked to agree): one that names a commit outside the history of `HEAD` and `origin/main`, or a strong cited one that names nothing; write another repository's as `<name>@<hash>` or a URL, a value in backticks | `tools/check/tracked-hashes.allow`, `<hash> \| <reason>`, for a hash of another repository that has to stand alone |
| [`wildcard-binds.py`](../tools/check/wildcard-binds.py) | in the test source sets, the harness modules and the samples' tests, a socket bound to the wildcard address in a file that talks to loopback (`127.0.0.1`, `::1`, `localhost`, `getLoopbackAddress()`, ktor-server's `rawHttp`/`slowHttp`): a `tlsConnector`/`sslConnector`/`plainConnector`/Ktor `connector` without `host`, `host = "0.0.0.0"` or `"::"`, a wildcard `InetSocketAddress` handed to a bind or an open (also through a local `val`, or a `val` holding the wildcard host), `java.net.InetSocketAddress(port)`, a bare `"0.0.0.0"` argument of a bind, `.bind(port)`, `.bind(port = ...)`, `.bind()`, `.bind { }`, `.bind(null[, backlog])` or `.bind(localAddress = null)` without an address, `embeddedServer(..., port = ...)` or `embeddedServer(factory, port)` without `host`, `ServerSocket(port[, backlog[, null]])`, `DatagramSocket()`/`DatagramSocket(port)`/`DatagramSocket(port, null)`, an interop server without `host`; in a test source set that runs on Kotlin/Native (any but `jvm*Test` and `android*Test`), loopback or not, a ktor-network `aSocket(...).udp()`/`.tcp()` (a `.configure` between them included) bound to an IPv6 address (a literal, also with a zone ID or as a raw string, an `InetSocketAddress` by position or by `hostname =`, or a `val` whose initializer holds one; a wildcard `"::"` the other rules report counts once), which ktor-network on Native binds as the wildcard `::` and whose datagrams to `::1` never arrive (KTOR-10017: bind with `DatagramIo.open` or `bindTcp`); an entry that matches nothing. On macOS a wildcard socket shares its port with one another process holds on 127.0.0.1, and traffic to 127.0.0.1 reaches that one | `tools/check/wildcard-binds.allow`, `<path> \| <line> \| <reason>` |

What the checks cannot see: `test-discovery.py` reads the brace structure of the sources, not their types, so a test
whose value comes through a lambda (`= runBlocking { ... }`, a fixture helper) is judged by `test-bytecode.py` alone, and
that one sees the JVM and Android compilations and the samples' only (a test only in an Apple, Linux or Windows source set
is not read there), and a test inherited from a class of another class directory is not followed. `test-sleeps.py` resolves a helper by its name, package and imports, not by types: two
same-named functions both visible to a file (overloads, members of different classes of one package) are taken for one,
a helper of the main sources (`kuicksilver-testing`) is not followed, a wait written as a busy loop over the clock is no
call it counts, and a new file Git takes for a copy of a file that lost sleeps may take them over. `env-apis.py` matches names, so a lookup
reached through a function of another name (a wrapper) is not seen. `rfc-tests.py` checks that a named test exists, not
that it tests what the row claims. `reproducers.py` knows a reproducer by its name only: one committed under another name
(`seed-*`, a name given with `-exact_artifact_path` or another `-artifact_prefix`) is not asked for an entry, a guard of a
ksl harness reproducer can only be a JVM test of `kuicksilver-native` (the C tests of `tools/c-test.sh` are not named),
a live entry's expected text is only as specific as it is written (a message or a stack frame, not an exception class),
a fix is matched to its plant by the content of the removed lines (a plant that deletes a line equal to one the fix
added, elsewhere in the same file, passes, and so does any edit to a file a fix commit changed), and a plant is a patch a reviewer reads (one that makes a harness throw the expected
text would pass the verifier); whether the records hold is checked weekly and by hand, not on every change. `fuzz-formats.py` and the replay see what a
program's trace says it decoded. `FuzzTraceTest` checks the trace of the two connection programs: every flag and outcome
constant must have its name in the trace, and the constant, value and trace name `tools/fuzz/formats/flags.txt` gives it
(the compiled programs against the same table `fuzz-formats.py` reads from the sources, so a renamed, moved or duplicated
flag fails both), and over every value of the flags byte, of an operation byte and of the 0-RTT
outcome byte, appended to one fixed program, two values with one trace must end alike: the same state, close code and
reason, collection sizes and counters on each side, and, for the connection program, the same bytes of every datagram
either side sent and of every stream byte and datagram an application read (for the 0-RTT program, whose bytes real TLS
randomizes, the length of every datagram and the kind and stream of every event). Not seen: a meaning that fixed program
never reaches (PMTUD switched off in a run too short to probe, a branch only an earlier operation it lacks would open),
a meaning that leaves no trace on the wire, in what the applications read or in those counters before the run ends (a
timer set to fire later), a 0-RTT meaning that changes datagram contents but not their lengths or events, and a meaning
given to a byte read later than the one swept; nor is a decoder change in the other traced programs that their trace does not state. A
decoding that depends on the run (ConnProgram's application calls read nothing for a side without a connection) changes
with a change to the library, not only to the decoder: it fails as a changed decoding and needs its reason. The other
programs trace only what the input decides (the HTTP/2 server target states all its pieces, also those after the core
closed). Targets listed in
`untraced.txt` are not covered (most read the input as the bytes of what they parse; `tls.zeroRttHello`,
`ktor-network.inflate`, `ktor-network.wsGuard`, `client.h1Response`, `server.h1Request` and `quic.rememberedTicket` have
small decoders not traced yet; `server.proxyHeader` reads only a mode byte before the header's own bytes), and neither is a Jazzer target that is not in the campaign's table
(`BbrInvariantFuzzTest`). The reason rule needs the history: the hosted lint job checks out all of it and compares a push to `main` or `release/**` with the commit before it, anything else with its merge base with `origin/main` (`KSL_FUZZ_FORMATS_BASE`); without a base it skips the rule and says so.

`deadline-sites.py` resolves the kotlinx functions exactly from each file's imports, but its timer and select forms are
syntactic: a deadline through another library (Ktor's `HttpTimeout`), through a project helper (only the helper's own
definition is a site), a timer that neither begins with `delay` nor cancels after it, or one started otherwise than by
`launch`/`async` (a `Timer`, `invokeOnTimeout`) is not seen. `test-hooks.py` matches hooks by name and owner, not by
types (writes are `=`, `+=`, `-=`, `++`, `--` and a property reference's `set`; a scope function on the owner names it;
a reset after `if`, `else` or a `when` branch counts for nothing): a hook set through reflection or through a variable
holding its object (when an instance property shares its name), a global `val` holding mutable state (an
`AtomicReference`, a `MutableStateFlow` set through `.value`), a name not ending in `ForTest`, a reset skipped by an early
`return` in its `finally`, and background work of an earlier test that outlives the reset are not seen; there is no
runtime check (the JVM cannot read a static field without initializing its class). `tracked-hashes.py` sees
what `commit-msg.sh` sees, in text files only, and the CI `lint` job's shallow clone only lists what it would fail. `wildcard-binds.py`
reads Kotlin and Java syntax, file by file: an address built in another file or passed as a parameter, a wildcard in a
string template or a constant of another file, a file that reaches loopback only through another file's helper (other than `rawHttp`/`slowHttp`), a null
address held in a variable (`DatagramSocket(0, addr)` with `addr = null`), a port by position held in a variable neither
declared as an `Int` nor named like a port (`embeddedServer(Netty, p)`), an IPv6 address a ktor-network bind takes from a parameter or another file or builds in a string template, an IPv6 `InetSocketAddress` held in a variable, a ktor-network bind not chained to its `aSocket(...).udp()`/`.tcp()` (a builder held in a variable, a call between them other than `configure`), and scripts or external peers are not seen; library code is out of its scope (the ktor-client HTTP/3 pool and
`QuicConnection.rebind` pick the loopback address for a loopback peer themselves). It also reports two false findings, to judge in
`wildcard-binds.allow`: a `.bind(null, x)` of something that is not a socket, and `embeddedServer(factory, x)` whose `x`
is named like a port but is not an `Int` (read as the port by position).

**Merging the locks.** `test-count.lock` has one sorted line per test, so two branches that add tests to different
classes merge without a conflict. On a conflict in any lock (`test-count.lock`, `test-sleeps.lock`, `rfc-tests.lock`),
take either side, run the check with `--update` on the merged tree, and read the diff of the lock against each parent:
a line of `test-count.lock` removed there is a test the merge dropped, a finding of the review rather than a conflict to
resolve by hand (in the other two locks a removed or lowered line is a gain).

The subject check also runs as a Git `commit-msg` hook. To install it in a clone (all its worktrees share the hook; Git
runs a hook from the top of the working tree, so each worktree runs its own copy of the script):

```sh
hook="$(git rev-parse --git-path hooks/commit-msg)"
printf '#!/bin/sh\nexec bash tools/check/commit-msg.sh "$1"\n' > "$hook"
chmod +x "$hook"
```

The hook reads the first line of the message that is not a comment; Git's own merge, revert and autosquash subjects
(`Merge ...`, `Revert "..."`, `fixup! ...`) pass there, and the gate fails a `fixup!` that was not squashed.

**Cited hashes.** A rebase or a rewrite of the dates gives every commit a new hash, and a message that cites an old one
points at nothing. `commit-msg.sh` reads the whole message (the hook: without `#` lines and below the `git commit -v`
cut) for words of 7 to 40 hex digits standing alone, not after `/ @ # = + -` or a single `.` (paths, URLs,
identifiers; `a..b` counts) and not followed by `...` (a truncated value). A word is strong when it is lower case, has
a digit and a letter and is not quoted; a number (`40636584799`), a word like `defaced`, an upper-case or a quoted
value (`` `ca5babe14fa53a74` ``) is weak. It is cited after `commit`, `commits`, `review of`, `fix of`, `fixes`,
`fixed in`, `follow-up to`/`of`, `reverts`, `since`, `before` or `after`, and so are the next hashes of a list after
one (`Review of a, b and c`). A word that names a commit in this clone (also one only the reflog keeps) fails unless
one commit with that prefix is in the history of the tip or of `origin/main` (a published commit is never rewritten;
strong words anywhere, weak ones when cited); a strong cited word that names no commit fails too (a value after
`since` or `after` is quoted in backticks), and any other word is taken for a value. Each word counts once per
commit. The message is read bytewise (`LC_ALL=C`, so text in any encoding is read), and a scan that fails is an
error (exit 2), never a pass. Write another repository's or another
branch's commit as `<name>@<hash>` (`quic-go@432b156`) or as a URL. Commits already on `origin/main` are not read, so
the stale citations published before the check stay; Git's `(cherry picked from commit ...)` line names the source on
another branch and is not read. The CI `lint` job checks out one commit (no `fetch-depth`), so it runs the negative
controls only; in a shallow clone the range check lists what it would fail as unchecked and passes.

What it cannot see: a stale hash whose object is gone (a fresh clone, after `git gc` dropped the reflog's) and that
follows no keyword (`c0ffee123 dropped the deadline`, an example hash); a weak word whose object is gone; a hash after `@`, in a path
or a URL; a hash on a `(cherry picked ...)` line; a message whose comment character is not `#` (the hook).

Not covered by the local gate: running the `mingwX64` test executables and the Windows C tests (`ksl_test.exe`;
hosted CI only), the C tests under sanitizers
on Linux, and a physical iOS device ([ios.md, Device checklist](guide/ios.md#device-checklist)). Interop results and
their analysis are in [docs/spec/interop.md](spec/interop.md).

### Proposed check: lossless hand-offs between coroutines

Not in the gate yet; it is meant to join the static checks under `tools/check` once their shared Kotlin scanner is on
`main`. A coroutine channel's `receive` has a prompt cancellation guarantee: an element already handed to a receiver
that is cancelled before it resumes is dropped unless the channel has `onUndeliveredElement`, and a `flow {}` builder's
`emit` checks the collector's job after the element was taken. Where the element is data or ownership (a capsule, a
request, a peer's stream, a pooled buffer), that is a loss or a leak; `HandOffQueue` in kuicksilver-http3 is the
lossless form. The check would flag, in production source sets:

- a `Channel(...)` whose element type is not `Unit` (declared or inferred from the property type) without an
  `onUndeliveredElement` argument or trailing lambda, when one of `receive`, `receiveCatching`, `onReceive`,
  `receiveAsFlow`, `consumeAsFlow` or `for (x in ch)` reads it;
- `produce`, `actor`, `callbackFlow` and `channelFlow` whose element type is not `Unit`;
- `flow { ... emit(<call that takes an element>) }`, the shape that loses an element to a collector cancelled while it
  ran.

- `select { ch.onReceive { ... } }` on a channel that is exposed publicly as a `ReceiveChannel`;
- a public `Flow` backed by an ownership queue (as `CapsuleStream.capsules` is) whose KDoc does not carry the operator
  caveat: `buffer`, `flowOn`, `conflate`, `produceIn`, `shareIn` and `stateIn` collect ahead in another coroutine and lose
  what they took and had not delivered when the collection is cancelled.

Each finding is either fixed or listed in an allowlist with its reason ("HTTP datagrams: unreliable by RFC 9297",
"single internal consumer, cancelled only with its connection"). Negative controls feed it the forms a regex misses:
an element type inferred from a factory function or a typealias, a channel exposed as `ReceiveChannel` and read in
another file, `select { ch.onReceive }`, comments and string templates that look like code.

## 6. Hosted CI

[`.github/workflows/build.yml`](../.github/workflows/build.yml) is the CI counterpart of the local gate: the same step
names, and the same module and interop case lists from [`tools/ci/matrix.sh`](../tools/ci/matrix.sh). It runs on pushes
to `main` and `release/**`, on pull requests to them, weekly, and by hand. The QUIC Interop Runner jobs run only weekly
and by hand, so hosted CI does not repeat every local step on every push. Its jobs: `lint`; the OpenSSL
builds in Docker; `linux` (x64 and arm64: C tests, `libksl.so`, JVM suites, system OpenSSL); `linux-native` and
`linux-native-arm64` (Kotlin/Native test executables; `linux-native` also runs h2spec against the linuxX64 server); `windows` (the `mingwX64` test executables and the C tests on a
Windows runner); `windows-jvm` (JVM suites on Windows against the mingw-w64 dll); `windows-loops-bench` (by hand only, with `only=windows-loops-bench`: `MultiLoopBenchmark` on Windows, not a gate); `openssl-next` (weekly, or by hand with `only=openssl-next`: the newest OpenSSL 4.x built on linux-x64 and macos-arm64 with the C tests and a JVM smoke test; `continue-on-error`, never required, no artifact); `apple` (ABI dumps, ASan C tests, JVM suites, the Intel-Mac library, the double build) and `apple-native` (`macosArm64`
and `iosSimulatorArm64` suites, `iosArm64` compiled, the release `Kuicksilver.xcframework` built); `android` (API 24 and 35 emulators); `jdk-compat`
(tests on JDK 17 and 25); `jvm-jar` and `consumer-smoke` (the jar with all five JNI libraries, a sample built from a
local publication); and, weekly or on request, the QUIC Interop Runner against the six peers. Nothing in it publishes,
signs or reads a secret, and pull requests from forks run with read-only rights; a maintainer approves the workflow
runs of every pull request from an outside contributor before they start (repository setting).

Every job that runs tests or builds an artifact also uploads a `verify-<job>` artifact: the test counts, outcomes and
artifact sizes of that job and nothing of the runner (`tools/docs/verify.py collect`). For a release, `pages.yml` turns
the artifacts of the release commit's green run into the "How we verify" pages of the documentation site (platform matrix,
engine interop, conformance suites, fuzzing, sizes, benchmarks, the RFC compliance summary), and refuses data of any
other commit or run ([release.md](release.md), "Every release", step 9).

Hosted CI is not the release gate: a release needs the local gate record (stage 5). A repository ruleset (id 27195213)
covers the default branch and `refs/heads/release/*`: they cannot be deleted and take no non-fast-forward push, and
nobody can bypass it. It requires no status check or pull request, so nothing requires a hosted run to be green before a
change lands; the hosted results are read, not enforced. The other workflows:

- [`codeql.yml`](../.github/workflows/codeql.yml): CodeQL security queries over the C shim and the Kotlin JVM code, on
  pull requests and pushes to `main` and `release/**`, and weekly;
- [`scorecard.yml`](../.github/workflows/scorecard.yml): OpenSSF Scorecard, weekly and on pushes to `main`;
- [`gradle-wrapper.yml`](../.github/workflows/gradle-wrapper.yml): `gradle/wrapper/gradle-wrapper.jar` must be the jar
  of an official Gradle release (Gradle's wrapper-validation action), on pull requests and pushes to `main` and
  `release/**`; a single short job, because Scorecard's Binary-Artifacts check accepts the checked-in jar only when such
  a workflow has a successful run for the newest commit of `main`;
- [`perf.yml`](../.github/workflows/perf.yml): the interop runner's throughput measurements against the floors of
  `tools/interop/perf-thresholds.json`, by hand only (shared runners are too noisy for a weekly verdict; the workflow
  is disabled in the repository settings until the maintainer enables it again); the floors warn and do not fail yet;
- [`fuzz.yml`](../.github/workflows/fuzz.yml): a fuzzing campaign, one runner per target, weekly (2 hours per target)
  and by hand. A finding fails the job and notifies the maintainers; its reproducer and logs are never uploaded,
  because artifacts of a public repository are public and a finding stays private until it is fixed (that a target
  found something is visible in the public run, what it found is not). Its `reproducers` job runs
  `tools/fuzz/reproducers-verify.sh`: with each plant of `tools/fuzz/reproducers.txt` applied in turn, every live
  reproducer must fail again with its recorded failure, every dead one must still pass, and every guard test must fail;
- [`release.yml`](../.github/workflows/release.yml): a hosted release, not used ([release.md](release.md#alternative-the-release-workflow-not-used));
- [`interop-image.yml`](../.github/workflows/interop-image.yml): publishes the interop images of a released version to
  GHCR, by hand;

## 7. Before a release: soak, fuzzing, benchmarks

These run by hand on the maintainer's machine; each has a computed verdict, not a judgement.

- **Soak.** `kuicksilver-soak` runs the whole stack on real UDP for hours against a weighted mix of transfers, aborts,
  idle timeouts, stateless resets, migrations, 0-RTT, endpoint and client churn and Ktor requests, and samples memory,
  descriptors, threads, native objects and the library's own tables. A run passes when every series is flat after
  warm-up, every countable resource returns to its idle baseline after the load stops, and unexpected failures stay
  under 0.5% ([CONTRIBUTING.md, Tests](../CONTRIBUTING.md#tests), "Soak and churn"). Before a release: 24 to 72 hours.
  For 0.2.1 these were a 24-hour Kotlin/Native soak and a 37-hour JVM soak ([roadmap.md](roadmap.md)).
- **Fuzzing campaigns.** [`tools/fuzz/campaign.sh`](../tools/fuzz/campaign.sh) fuzzes every Jazzer target (TLS, QUIC,
  HTTP/3, QPACK, HTTP/2, HPACK, HTTP/1.1, WebSocket, HTTPS records, and stateful fuzzers of QUIC and HTTP/2 connections; `campaign.sh list`) and the libFuzzer harness of the `ksl` C parsing
  code, resumably and in slices, locally and in the weekly hosted run (stage 6); the grown corpora are minimized into
  `tools/fuzz/corpus/`, which the gate replays. A Jazzer target's corpus input is named by the SHA-1 of its bytes, as the
  merge names it, and `CommittedCorpusReplayTest` fails on one that is not (a rewrite renames the file); the ksl harness's
  inputs (`ksl.parsers`) are named by the FNV-1a 64 of their bytes (`tools/fuzz/ksl/fnv.h`, as the driver names them), and
  `tools/c-test.sh` fails on one that is not before it replays them (`tools/fuzz/ksl/corpus-names.c`; `--rename` renames, and
  `campaign.sh minimize` and `prune` rename a merge's output with it, since libFuzzer's merge on Linux names inputs by SHA-1). A crash becomes a committed input, a unit test and a fix, and is
  handled as a private vulnerability report until it is fixed when it may be reachable by a peer. For 0.2.1: 2 hours per target.
  The weekly hosted run is `fuzz.yml`, whose findings stay private; ClusterFuzzLite is not enabled, because it would
  publish a finding's input (an artifact) and stack trace (the job log). `.clusterfuzzlite/` is kept OSS-Fuzz-compatible
  for a future OSS-Fuzz application: it builds the same Jazzer targets (the ksl harness aside) the way OSS-Fuzz builds a
  project, checked by hand with `docker build -f .clusterfuzzlite/Dockerfile`, the image's `compile`, and
  `run_fuzzer <target>` in the OSS-Fuzz base runner image.
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

A prerelease can be published on GitHub only, never on Maven Central, with `--github-prerelease`
([release.md](release.md#prereleases-on-github-only)); 0.3.0-rc1 is published this way, and the final 0.3.0 goes to
Central; without the mode the script refuses a prerelease unless `--central-prerelease` asks for Central. The mode
refuses a final version, runs the same preconditions, build, checks, signing and home-directory scan, does not read or
pass on the Central Portal token and uploads nothing. Instead of the deployment it writes a signed Maven
repository zip of the publication (every artifact with its POM, Gradle module metadata, `.asc` and checksums), a short
file that says how to consume it, and a signed `SHA256SUMS` of every asset, for the maintainer to attach to the GitHub
prerelease. The Swift package commit is prepared as for a release, its binary target the zip of the GitHub prerelease.
Its tag is immutable, so it is pushed last, in this order: an empty package built for the iOS Simulator and iOS
against the local zip (`tools/release/swift-package-check.sh local`); the GitHub prerelease as a draft with the
xcframework zip, whose asset and GitHub's digest are checked against `Package.swift` (`swift-package-check.sh remote
--draft`) before it is published, and the public URL once it is (`remote`); then the Swift package tag, after
`swift-package-check.sh prepush`; then an empty package resolved with `exact: "<version>"` (`resolve`). Commits and
tags are made in UTC, and the checks refuse any other time zone. The clone of the Swift package gets a pre-push hook
([`tools/release/swift-package-pre-push.sh`](../tools/release/swift-package-pre-push.sh)) that runs the same checks on
every push of it, so the immutable tag does not depend on running them by hand: a tag is pushed only as the signed,
annotated tag of the release identity, never as a bare commit, and the clone's own git config carries that identity
(`user.name`, `user.email`, and `kuicksilver.swift.author`, which the checks read): the release key's identity
`Kuicksilver <hello@kuicksilver.io>` for its commit and its tag, whatever the Mac's global one is. The documentation site is not built
for a prerelease.

### Privacy pre-push hook

Nothing published may say who or where the maintainer is: no time zone in a commit or tag, no identity but the
configured one, no name, home directory or host name in an author, committer, commit message or added line; and a
tag (only release tags are pushed here, whatever their name) is pushed only as an annotated tag signed by the release
key (checked against `tools/release/kuicksilver-release-key.asc` and its pinned fingerprint).
[`tools/hooks/pre-push`](../tools/hooks/pre-push) refuses such a push;
`tools/release/local-release.sh` refuses to run until it is installed in the checkout and the names and the identity
are configured, while the checkout's `user.name <user.email>` is not that identity, and while the tagger is not a user
ID of the release key (GitHub shows a signed tag as Verified only then). Release tags are made with the tagger per
command (`git -c user.name=… -c user.email=… tag -s`, as the script prints it), so commits keep the checkout's identity. The
hook checks the commits the remote does not have (by a named remote's tracking refs, else by listing it; a remote that
cannot be listed refuses the push), also after a force push. The
names live in the checkout's git config, never in the repository (a space in a name matches ' ', '.', '_', '-' or
nothing; any case):

```
ln -sf ../../tools/hooks/pre-push "$(git rev-parse --git-common-dir)/hooks/pre-push"
git config --add kuicksilver.privacy.names "<first name> <last name>"     # once per name, alias or spelling
git config kuicksilver.privacy.identity "<name> <email>"                   # the only author and committer
git config kuicksilver.privacy.tagger "Kuicksilver <hello@kuicksilver.io>"  # the only tagger: the release key's identity
```

Commit and tag with `TZ=UTC`. The same names, the user and host names of the Mac and its temporary directories are
also looked for in every release output by `tools/check/build-paths.py`, at scan time.

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
