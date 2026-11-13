<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpenSSF Best Practices: answers for the passing level

Prepared answers for the [OpenSSF Best Practices](https://www.bestpractices.dev/) questionnaire, passing level, so the
entry can be filled in from one place. The project has **not been submitted yet**; the maintainer submits it, then adds
the badge to the README (a commented placeholder is there).

Each criterion has an answer (**Met**, **Unmet**, **N/A**, or **Owner** where only the maintainer can answer) and the
evidence in this repository. Where the answer depends on how the criterion is read, the note says so. Re-check every
answer against the repository when submitting; this file is not kept in sync by any tool.

## Basics

| Criterion | Level | Answer | Evidence |
|---|---|---|---|
| `description_good` | MUST | Met | [README.md](../README.md): what Kuicksilver is (QUIC, HTTP/3 and TLS for Kotlin Multiplatform, Ktor engines) and the problem it solves |
| `interact` | MUST | Met | README: Maven Central coordinates, quick start; [CONTRIBUTING.md](../CONTRIBUTING.md); GitHub issues with templates ([`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/config.yml)) |
| `contribution` | MUST | Met | [CONTRIBUTING.md, Proposing a change](../CONTRIBUTING.md#proposing-a-change) |
| `contribution_requirements` | SHOULD | Met | CONTRIBUTING: style, tests first, the [pull request checklist](../CONTRIBUTING.md#pull-request-checklist), the Developer Certificate of Origin |
| `floss_license` | MUST | Met | Apache-2.0 ([LICENSE](../LICENSE)); the bundled OpenSSL is Apache-2.0 too ([NOTICE](../NOTICE)) |
| `floss_license_osi` | SUGGESTED | Met | Apache-2.0 is OSI-approved |
| `license_location` | MUST | Met | `LICENSE` at the repository root |
| `documentation_basics` | MUST | Met | README, the guides in `docs/guide/` ([QUIC](guide/quic.md), [TLS](guide/tls.md), [HTTP/3](guide/http3.md), [Ktor](guide/ktor.md), [iOS](guide/ios.md)), [architecture.md](architecture.md) |
| `documentation_interface` | MUST | Met | KDoc on public declarations, required by CONTRIBUTING (Style: "Explicit API") and checked in review; `explicitApi()` enforces visibility modifiers, not KDoc. Javadoc jars on Maven Central (Dokka), the [configuration reference](guide/configuration.md), [stability.md](stability.md) |
| `sites_https` | MUST | Met | The project site is the GitHub repository (HTTPS); artifacts come from Maven Central over HTTPS. Owner: if `kuicksilver.io` serves pages, they must be HTTPS only |
| `discussion` | MUST | Met | GitHub issues: searchable, addressable by URL, open to new participants, no proprietary client needed (GitHub Discussions are not enabled) |
| `english` | SHOULD | Met | Documentation, code, issues and commits are in English (the repository itself; CONTRIBUTING, Style) |
| `maintained` | MUST | Met | Releases 0.2.0 (2026-10-18) and 0.2.1 (2026-11-04); active `main` ([CHANGELOG.md](../CHANGELOG.md)) |

## Change control

| Criterion | Level | Answer | Evidence |
|---|---|---|---|
| `repo_public` | MUST | Met | <https://github.com/kuicksilver/kuicksilver> |
| `repo_track` | MUST | Met | git: who changed what and when |
| `repo_interim` | MUST | Met | Work between releases is on `main` (and `release/<X.Y>.x` for patches), not only at release time |
| `repo_distributed` | SUGGESTED | Met | git |
| `version_unique` | MUST | Met | One version per release; [`tools/release/local-release.sh`](../tools/release/local-release.sh) refuses a version already on Maven Central |
| `version_semver` | SUGGESTED | Met | Semantic Versioning (CHANGELOG header), 0.x as pre-1.0 |
| `version_tags` | SUGGESTED | Met | Signed tags `v0.2.0`, `v0.2.1` ([release.md](release.md#every-release), step 6) |
| `release_notes` | MUST | Met | [CHANGELOG.md](../CHANGELOG.md) (Keep a Changelog) and the GitHub release of each version |
| `release_notes_vulns` | MUST | Met, check | Each release's **Security** heading lists the vulnerabilities it fixes (for example 0.2.1). None of them had a CVE yet; [SECURITY.md](../SECURITY.md) commits to GitHub Security Advisories with CVEs from now on |

## Reporting

| Criterion | Level | Answer | Evidence |
|---|---|---|---|
| `report_process` | MUST | Met | GitHub issues with templates for bugs, features and interop ([`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/config.yml)) |
| `report_tracker` | SHOULD | Met | GitHub issues |
| `report_responses` | MUST | Owner | The majority of bug reports of the last 2 to 12 months acknowledged. Check the issue list before submitting (few reports so far) |
| `enhancement_responses` | SHOULD | Owner | Same, for enhancement requests |
| `report_archive` | MUST | Met | GitHub issues are public and searchable |
| `vulnerability_report_process` | MUST | Met | [SECURITY.md](../SECURITY.md), linked from the README and the issue chooser |
| `vulnerability_report_private` | MUST | Met | GitHub private vulnerability reporting (SECURITY.md, "Reporting a vulnerability") |
| `vulnerability_report_response` | MUST | Met | SECURITY.md: acknowledgement within 3 business days, assessment within 14 days. Owner: no report has exceeded 14 days unanswered |

## Quality

| Criterion | Level | Answer | Evidence |
|---|---|---|---|
| `build` | MUST | Met | Gradle (`./gradlew`), [CONTRIBUTING.md, Building](../CONTRIBUTING.md#building) |
| `build_common_tools` | SUGGESTED | Met | Gradle, clang or gcc, Docker |
| `build_floss_tools` | SHOULD | Met, with a limit | JVM, Linux, Windows (mingw-w64) and Android build with FLOSS tools (OpenJDK, Gradle, clang/gcc, the Android NDK's clang). The Apple targets need Xcode, which is not FLOSS; that is a platform requirement |
| `test` | MUST | Met | Unit and integration tests in every module (`commonTest`, `jvmTest`, native tests), the `ksl` C tests ([`tools/c-test.sh`](../tools/c-test.sh)); FLOSS (kotlin-test, JUnit) |
| `test_invocation` | SHOULD | Met | `./gradlew :<module>:jvmTest`, `check`; the whole gate is [`tools/ci/local-matrix.sh`](../tools/ci/local-matrix.sh) |
| `test_most` | SUGGESTED | Met | JVM line and branch coverage with Kover (`-Pkuicksilver.coverage :koverHtmlReportJvmTests`, CONTRIBUTING, Tests); no threshold, by decision |
| `test_continuous_integration` | SUGGESTED | Met | [`.github/workflows/build.yml`](../.github/workflows/build.yml) on pushes and pull requests to `main` and `release/**`; the local gate before every release ([process.md](process.md)) |
| `test_policy` | MUST | Met | CONTRIBUTING, Tests: a test that fails before the fix, `negative_*` controls for security checks |
| `tests_are_added` | MUST | Met | Fixes in the CHANGELOG name their tests; commits add the failing test with the fix |
| `tests_documented_added` | SUGGESTED | Met | CONTRIBUTING, Tests, and the pull request checklist |
| `warnings` | MUST | Met | C: `-Wall -Wextra -Werror` in every build script of `ksl` (`tools/build-jni.sh`, `tools/build-ksl-a.sh`, `tools/build-android-so.sh`, `tools/c-test.sh`); Kotlin: `explicitApi()` and ktlint in `check` |
| `warnings_fixed` | MUST | Met | C warnings fail the build; ktlint findings fail the gate. Kotlin compiler warnings are errors in the main and test compilations of the library modules (the `kuicksilver.kmp` convention plugin sets `allWarningsAsErrors`; `-Pkuicksilver.warningsAsErrors=false` turns it off locally, e.g. to try a dependency bump) |
| `warnings_strict` | SUGGESTED | Met | C: `-Werror` |

## Security

| Criterion | Level | Answer | Evidence |
|---|---|---|---|
| `know_secure_design` | MUST | Owner | A statement about the developers. Evidence to cite: [threat-model.md](spec/threat-model.md), ADRs in [docs/adr/](adr/README.md) |
| `know_common_errors` | MUST | Owner | A statement about the developers. Evidence to cite: the [Review checklist](../CONTRIBUTING.md#review-checklist), the threat model's mitigations |
| `crypto_published` | MUST | Met | Only published, reviewed algorithms through OpenSSL 3.5 LTS (TLS 1.3, TLS 1.2 with ECDHE and AEAD suites, QUIC packet protection per RFC 9001) |
| `crypto_call` | SHOULD | Met | Cryptography is called from OpenSSL through the `ksl` shim; nothing is reimplemented |
| `crypto_floss` | MUST | Met | OpenSSL (Apache-2.0) |
| `crypto_keylength` | MUST | Met | What Kuicksilver chooses meets the NIST minimums: key exchange groups X25519MLKEM768, X25519, P-256, X448, P-384, P-521 (`kuicksilver-native/src/c/ksl_ctx.c`); AEADs with 128- or 256-bit keys; no finite-field DH or DSA (`no-dh`, `no-dsa` in [`tools/openssl/configure-flags.txt`](../tools/openssl/configure-flags.txt)); OpenSSL 3.5's default security level 2 (112 bits: RSA keys of 2048 bits or more; `ksl` does not lower it) applies to the endpoint's own certificate and to chains OpenSSL verifies. The peer's chain is held to the same 112 bits under every trust configuration although the JDK, Android and Windows verifiers accept 1024-bit RSA: under `TrustConfig.Platform` on the path the platform verifier built, under `Custom` and `Tofu` on the presented chain ([RFC 9846 §4.5.1.3](spec/rfc/9846.md#s4-5-1-3-weak-certificate-signatures-and-keys)) |
| `crypto_working` | MUST | Met | Broken algorithms are compiled out of the bundled OpenSSL: SSL 3, TLS 1.0 and 1.1, RC4, DES, MD4, legacy provider (`configure-flags.txt`) |
| `crypto_weaknesses` | SHOULD | Met | The default TLS 1.2 list is ECDHE with AES-GCM or ChaCha20-Poly1305 only (`ksl_ctx.c`, `TLS12_PROFILE_CLIENT`, `TLS12_PROFILE_SERVER`); no CBC or SHA-1 suites by default |
| `crypto_pfs` | SHOULD | Met | TLS 1.3 and QUIC always use (EC)DHE; the default TLS 1.2 suites are ECDHE only. An application can pass its own TLS 1.2 list |
| `crypto_password_storage` | MUST | N/A | Kuicksilver stores no passwords |
| `crypto_random` | MUST | Met | Connection IDs, tokens, stateless-reset secrets and ticket keys come from OpenSSL's `RAND_bytes` (`ksl_crypto.c`, `KslRandom.kt`) |
| `delivery_mitm` | MUST | Met | Maven Central over HTTPS, every artifact signed with the release key; [verifying.md](verifying.md) |
| `delivery_unsigned` | MUST | Met | No hash is fetched over HTTP; signatures and Gradle dependency verification ([verifying.md](verifying.md#in-your-build-gradle-dependency-verification)) |
| `vulnerabilities_fixed_60_days` | MUST | Met, check | No publicly known medium or higher vulnerability unpatched for more than 60 days. Check the Security tab before submitting |
| `vulnerabilities_critical_fixed` | SHOULD | Met | SECURITY.md: Critical and High fixed within 30 days of the assessment; OpenSSL Critical and High within 72 hours |
| `no_leaked_credentials` | MUST | Met | Credentials and the signing key live outside the repository ([release.md](release.md#once-accounts-keys-dns)); the keys in the repository are test keys for test certificates, and the public release key |

## Analysis

| Criterion | Level | Answer | Evidence |
|---|---|---|---|
| `static_analysis` | MUST | Met | CodeQL with the `security-extended` queries over the C shim and the Kotlin JVM compilation ([`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml): pull requests and pushes to `main` and `release/**`, weekly); ktlint; the project's own static checks (sans-IO import rules and module layering: `checkQuicArchitecture`, `checkHttp3Architecture`, `checkHttp2Architecture`, `checkLayerDependencies`); shellcheck (`-S error`) over every tracked `*.sh` in the hosted lint job; the export, symbol-prefix and keylog checks of the native libraries. Check that the CodeQL workflow has run green before submitting |
| `static_analysis_common_vulnerabilities` | SUGGESTED | Met | CodeQL's security queries (above) |
| `static_analysis_fixed` | MUST | Met | ktlint, shellcheck and the architecture checks fail the build until fixed; CodeQL alerts of medium or higher severity are fixed or dismissed with a reason |
| `static_analysis_often` | SUGGESTED | Met | ktlint, shellcheck and the architecture checks on every gate and hosted CI run; CodeQL on pull requests and pushes to `main` and `release/**`, and weekly |
| `dynamic_analysis` | SUGGESTED | Met | Fuzzing: Jazzer targets and a libFuzzer harness of the C parsers ([`tools/fuzz/campaign.sh`](../tools/fuzz/campaign.sh)), weekly on GitHub-hosted runners ([`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml), 2 hours per target), committed corpora replayed by the gate; the network simulator's Monte-Carlo runs; soak runs ([process.md](process.md#7-before-a-release-soak-fuzzing-benchmarks)) |
| `dynamic_analysis_unsafe` | SUGGESTED | Met | The `ksl` C tests run under AddressSanitizer and UndefinedBehaviorSanitizer (`tools/c-test.sh`, gate step "c-tests: macos-arm64 (ASan/UBSan)"); the libFuzzer harness is built with sanitizers |
| `dynamic_analysis_enable_assertions` | SUGGESTED | Met | Tests and fuzzing run debug builds with assertions and the sanitizers on |
| `dynamic_analysis_fixed` | MUST | Met | A fuzz crash becomes a committed input, a unit test and a fix (CONTRIBUTING, Tests, "Fuzzing"); no known unfixed medium or higher finding |
