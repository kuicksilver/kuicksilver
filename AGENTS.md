<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Instructions for AI coding agents

These rules apply to any AI agent working in this repository. Human contributors: see [CONTRIBUTING.md](CONTRIBUTING.md).

## Where things are

- Architecture, invariants and the code map: [docs/architecture.md](docs/architecture.md). Read it first.
- Decisions: [docs/adr/](docs/adr/README.md). User guides: `docs/guide/` (with the option reference
  `docs/guide/configuration.md` and `docs/guide/troubleshooting.md`); API stability levels and version policies: [docs/stability.md](docs/stability.md). RFC coverage and interop results:
  [docs/spec/rfc-compliance.md](docs/spec/rfc-compliance.md). Threat model and the `negative_*` controls:
  [docs/spec/threat-model.md](docs/spec/threat-model.md).
- Modules: `kuicksilver-native` (C shim `ksl` in `src/c`, JNI in `src/jni`) → `kuicksilver-tls` → `kuicksilver-quic` →
  `kuicksilver-http3` → `kuicksilver-ktor-client` / `kuicksilver-ktor-server`; `kuicksilver-ktor-network` sits on
  `kuicksilver-tls`. A module depends only on the layer directly below it.
- Scripts: `tools/openssl` (pinned OpenSSL), `tools/prefix`, `tools/check`, `tools/ci`, `tools/interop`, `tools/fuzz`.

## Commands

```sh
./gradlew --max-workers=2 :<module>:jvmTest                  # e.g. :kuicksilver-quic:jvmTest
./gradlew --max-workers=2 :<module>:jvmTest --tests '<pattern>'
./gradlew --max-workers=2 :<module>:macosArm64Test           # Kotlin/Native, macOS host
bash tools/c-test.sh                                         # ksl C tests (ASan/UBSan)
./gradlew checkSpdxHeaders checkLayerDependencies :kuicksilver-quic:checkQuicArchitecture :kuicksilver-http3:checkHttp3Architecture
./gradlew :<module>:checkKotlinAbi                           # :<module>:updateKotlinAbi after an intended API change
bash tools/check/links.sh                                    # Markdown links
bash tools/check/doc-refs.sh                                 # doc paths, anchors, symbols; private markers in docs and comments
bash tools/check/rfc-table.sh                                # RFC compliance summary table format
```

Always pass `--max-workers=2`. The first build of a module compiles OpenSSL for the host; Linux and mingw OpenSSL builds
need Docker. Prefer module-scoped tasks: the root `checkKotlinAbi` builds every native target.

## Rules

- Work test-first: write the failing test, run it and see it fail for the expected reason, then fix. Security checks get
  a `negative_*` test. No `sleep`/`delay` waits: use virtual time, the simulator or `MemoryNetwork`.
- Keep the QUIC and HTTP/3 codecs sans-IO (no sockets, clocks, coroutines or default randomness there) and keep the
  layering; the architecture checks enforce both.
- Public API: `explicitApi()`, KDoc on every public declaration, new API under `@ExperimentalKuicksilverApi`, ABI dump
  updated in the same commit.
- Every new file starts with the SPDX header (`Copyright 2026 The Kuicksilver Authors` /
  `SPDX-License-Identifier: Apache-2.0`) in the file's comment syntax.
- Code, comments, KDoc, commit messages and documentation are in English.
- Commit messages: `<type>(<scope>): <what>`, a body that says why, and an `Assisted-by: <tool>[:<model>]` trailer.
  Do not use `Co-authored-by:` for an agent.

## Never

- Never add `Signed-off-by:` yourself; the human who reviews and commits the change signs off.
- Never push, publish artifacts, create releases or tags, or change repository settings.
- Never open, comment on or close issues or pull requests on your own.
- Never weaken a security check to make a test pass: host name verification, pins, the OpenSSL signature and SHA-256
  checks, the native library hash check, `negative_*` tests, size, export and glibc gates.
- Never change `gradle/openssl.toml` (pin, hash, key fingerprint) or the vendored OpenSSL key without being asked.
- Never read `SSLKEYLOGFILE` implicitly, log secrets, or copy key material into the Kotlin heap.
- Never put non-public vulnerability details into prompts of third-party services.
- Never edit generated files by hand: ABI dumps (`api/`), the QPACK tables and the seed corpora have generators.
