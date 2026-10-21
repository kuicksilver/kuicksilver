<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

Kuicksilver implements TLS, QUIC and HTTP/3 and ships a statically linked OpenSSL, so we treat security reports as our
highest priority. Thank you for reporting responsibly.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub's private vulnerability reporting:
<https://github.com/kuicksilver/kuicksilver/security/advisories/new> (repository tab **Security**, then **Report a
vulnerability**). Only the maintainers can see the report.

Please include:

- the affected version or commit, the platform (JVM, Android, Kotlin/Native target) and the module;
- what an attacker can do, and from where (network observer, malicious peer, malicious server, local);
- a reproduction: a test, a packet capture with a key log, or a minimal program;
- whether you used AI tools to find or describe the issue (it helps us judge the report, it does not lower its priority).

Hardening suggestions that are not exploitable may be filed as ordinary issues. If you are unsure, report privately.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Initial assessment (valid or not, severity, affected versions) | within 14 days |
| Fix released for Critical and High severity | within 30 days of the assessment |
| Public disclosure | coordinated with you; by default no later than 90 days after the report |

We keep you informed while we work on the fix, agree the disclosure date with you, and credit you in the advisory
unless you prefer otherwise. Advisories are published as GitHub Security Advisories, with a CVE requested through
GitHub. A few days before a security release we announce that a release with a security fix is coming, without
details, and the release's `CHANGELOG.md` entry lists the fix under **Security**. There is no bug bounty.

## Supported versions

| Version | Supported |
|---|---|
| latest 0.x release | yes |
| older 0.x releases | no — upgrade to the latest |

Kuicksilver is pre-1.0: only the latest 0.x release receives fixes. From 1.0 on, the latest minor release of each
supported major version will receive security fixes, and a major version will be supported for at least two years
after the next major version is released. Fixes land on `main` and ship in a patch release of the latest line, made
from its maintenance branch (`release/<X.Y>.x`, see [docs/release.md](docs/release.md#releasing-from-a-maintenance-branch)).

## OpenSSL

Every Kuicksilver artifact (JVM jars, the Android AAR, the Kotlin/Native klibs) contains a statically linked OpenSSL
built by this repository. Applications do not get OpenSSL updates from their operating system for it; they get them
from us, so we commit to the following.

- **Pinned release.** We use the OpenSSL 3.5 LTS branch. The exact release, the SHA-256 of its tarball and the
  fingerprint of the OpenSSL release signing key are pinned in [`gradle/openssl.toml`](gradle/openssl.toml); the build
  verifies the signature and the hash before compiling (`tools/openssl/fetch.sh`). The build configuration
  ([`tools/openssl/configure-flags.txt`](tools/openssl/configure-flags.txt)) compiles out everything the stack does
  not use (legacy protocols and ciphers, DTLS, OpenSSL's own QUIC and socket code, engines, dynamic modules, key
  logging, and more), which removes a large part of OpenSSL's attack surface.
- **Watching upstream.** The maintainers follow the openssl-announce list, which pre-announces security releases.
- **When OpenSSL publishes a fix**, we check the advisory against our configuration and release a Kuicksilver version
  with the fixed OpenSSL:

  | OpenSSL severity | Kuicksilver release with the fixed OpenSSL |
  |---|---|
  | Critical or High | within 72 hours of the OpenSSL release |
  | Moderate | within 14 days |
  | Low, or not reachable in our configuration | in the next planned release, with a note saying why it does not affect us |
  | Non-security 3.5.x patch release | within 30 days |

- **Version strings.** The OpenSSL version stays visible in the native libraries (and in the JVM jar manifest as
  `OpenSSL-Version` and `OpenSSL-SHA256`), so scanners can see which release you ship. Update Kuicksilver promptly when
  an OpenSSL advisory applies.
- **System OpenSSL.** On Linux, `ksl` can also be compiled against a system OpenSSL 3.5 or newer (`KSL_SYSTEM_OPENSSL`);
  published artifacts never do this. If you build that way, your operating system vendor is responsible for patching
  OpenSSL.
- **Not FIPS.** Kuicksilver is not FIPS-certified, and the bundled OpenSSL is built without the FIPS provider (no
  `enable-fips`, and `no-module`); see [docs/stability.md, OpenSSL](docs/stability.md#openssl). A build against a system
  OpenSSL that has a FIPS provider does not make Kuicksilver FIPS-validated either.
- **SBOM and provenance.** Each release from 0.2.1 attaches to its GitHub release a CycloneDX SBOM of every publication
  (with OpenSSL as a component: version, tarball SHA-256, CPE, configure flags) and a signed build provenance statement;
  see [docs/release.md, Supply chain](docs/release.md#supply-chain-sbom-and-provenance).
- **Verifying a release.** [docs/verifying.md](docs/verifying.md) shows how to check the signatures (release key
  `22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68`), the SBOM and provenance, and how to rebuild the native libraries that are
  reproducible and compare them with the published ones (`tools/verify/verify-release.sh`). A signature that does not
  verify, or a reproducible library that differs, is a vulnerability report.

A vulnerability in OpenSSL itself should be reported to the OpenSSL project
(<https://openssl-library.org/policies/general/security-policy/>). If it is reachable through Kuicksilver in a way
OpenSSL's advisory does not cover, report that to us as well.

## Scope

The threat model is in [docs/spec/threat-model.md](docs/spec/threat-model.md). In scope, for example:

- memory unsafety, undefined behaviour or a crash in the `ksl` C shim or its JNI/cinterop bindings;
- bypassing host name verification, a pin, `ExpectedName`, or the trust configuration in any way;
- unbounded memory or CPU growth driven by a peer, beyond the configured limits;
- nonce reuse, key or secret material leaking into the Kotlin heap, logs or files without the explicit key-log API;
- predictable connection IDs, Retry or stateless-reset tokens; amplification beyond the 3x limit of RFC 9000;
- a crash of an endpoint, or of other connections, caused by a single malicious peer;
- a tampered native library that loads anyway.

Out of scope:

- resource use within the limits you configured (raise or lower them for your threat model);
- a `TrustConfig.Custom` verifier, or a `KeylogSink`, that does what your code told it to do;
- secrets exposed through the explicit key-log API (`@DelicateKuicksilverApi`);
- side channels of the host (shared CPU caches, power analysis), traffic analysis, and compromise of the operating
  system or a root user on the host;
- bugs in OpenSSL that Kuicksilver does not make reachable (report them to OpenSSL);
- anything in `samples/`, test certificates and test keys, or the unpublished modules (`kuicksilver-testing`,
  `kuicksilver-bench`, `kuicksilver-interop`), unless it shows a flaw in a published module.

## Safe harbor

We consider security research carried out in good faith under this policy to be authorized. We will not pursue or
support legal action against you for accidentally violating this policy while trying to follow it, provided you:

- test only against systems you own or are allowed to test, and never against other people's servers or data;
- avoid privacy violations, data destruction and service degradation;
- give us reasonable time to fix the issue before any public disclosure.

If a third party takes legal action against you for research done under this policy, we will make it known that your
actions were authorized by us. If in doubt, ask us privately first.
