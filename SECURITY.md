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

Our own findings follow the same rule: a crash found by fuzzing (locally or in the weekly hosted fuzzing run, which
never uploads reproducers or crash logs) is kept private until it is fixed, and is disclosed as below if it was
reachable by a peer. That the hosted run of a fuzz target found something is visible to anyone (its job fails); the
input and the stack trace are not published.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Initial assessment (valid or not, severity, affected versions) | within 14 days |
| Fix released for Critical and High severity | within 30 days of the assessment |
| Public disclosure | coordinated with you; by default no later than 90 days after the report |

We keep you informed while we work on the fix, agree the disclosure date with you, and credit you in the advisory
unless you prefer otherwise. A vulnerability in Kuicksilver's own code is published as a GitHub Security Advisory of
this repository, with a CVE requested through GitHub, once the fixed version is on Maven Central; the advisory names the
affected and the fixed versions of the `io.kuicksilver` packages. A few days before a security release we announce that
a release with a security fix is coming, without details, and the release's `CHANGELOG.md` entry lists the fix under
**Security**. There is no bug bounty.

## Where to see the status

- **Advisories**: <https://github.com/kuicksilver/kuicksilver/security/advisories>, for vulnerabilities in Kuicksilver
  and for OpenSSL advisories that affect it (see [OpenSSL](#openssl)). GitHub reviews them for the GitHub Advisory Database
  (Maven ecosystem); once there, Dependabot alerts and other scanners that read it can tell a project that depends on
  an affected `io.kuicksilver` version.
- **Releases**: the `CHANGELOG.md` section of each version has a **Security** heading for security fixes, including
  OpenSSL updates, and the same text is on the version's GitHub release. *Watch → Custom → Releases* (or *Security
  alerts*) on the repository gets you a notification.

## Supported versions

| Version | Supported |
|---|---|
| the latest 0.x release (0.2.1 today; updated with each release) | yes: security fixes and OpenSSL updates |
| older 0.x releases | no — upgrade to the latest |
| unreleased code on `main` | fixes land there first; not a supported release |

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
- **When OpenSSL publishes a security advisory**, we check it against our configuration (the compiled-out features
  above) and against how Kuicksilver calls OpenSSL, and decide whether the issue is reachable through Kuicksilver. For
  every issue that is, we make a patch release of the supported line with the fixed OpenSSL (OpenSSL publishes the
  fixed release together with its advisory):

  | OpenSSL advisory | Kuicksilver patch release with the fixed OpenSSL |
  |---|---|
  | Critical or High, reachable through Kuicksilver | within 72 hours of the advisory |
  | Moderate or Low, reachable through Kuicksilver | within 7 days of the advisory |
  | Not reachable in our configuration or through our use of OpenSSL | in the next planned release, with a note saying why it does not affect us |
  | Non-security 3.5.x patch release | within 30 days |

  For a reachable issue we also publish a GitHub Security Advisory of this repository that names the OpenSSL advisory
  and CVE, the affected Kuicksilver versions and the fixed one ([Where to see the status](#where-to-see-the-status)).
  When we are not sure an issue is unreachable, we treat it as reachable.
- **Maven Central limits.** By agreement with Sonatype, the `io.kuicksilver` namespace has a monthly file and size
  quota that one release nearly fills, so planned releases come at most once a month ([docs/release.md, Publishing
  limits](docs/release.md#once-accounts-keys-dns)). A security release does not wait for the next month: it is
  uploaded to Central even when the month's quota is already used, and whether Central accepts a deployment above the
  quota is Sonatype's decision. This emergency path has not been needed yet. If Central refused such an upload, the
  advisory would say so, name the affected versions and any mitigation, and the release would follow as soon as Central
  accepts it. A 7-day patch for a Moderate or Low issue can likewise take the month's release slot and push the next
  planned release later.
- **What such a release goes through.** An OpenSSL patch release runs the full local gate on its release commit, like
  every release ([docs/release.md](docs/release.md#every-release)), but not the 24–72 hour soak that precedes a planned
  release, when nothing else changes: such a release only moves OpenSSL to a fixed 3.5.x release.

- **Version strings.** The OpenSSL version stays visible in the native libraries (and in the JVM jar manifest as
  `OpenSSL-Version` and `OpenSSL-SHA256`), so scanners can see which release you ship. Update Kuicksilver promptly when
  an OpenSSL advisory applies.
- **System OpenSSL.** On Linux, `ksl` can also be compiled against a system OpenSSL 3.5 or newer 3.x (`KSL_SYSTEM_OPENSSL`; 4.x is refused, prepared but not supported in 0.3.0);
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
