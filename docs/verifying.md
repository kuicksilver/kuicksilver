<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Verifying a release

How to check, without trusting the maintainer's machine, that the Kuicksilver artifacts you download are the ones the
project released and, for the native libraries, that they are what the tagged sources build. Each check below says what
it proves and what it does not.

A release is built, signed and uploaded from one maintainer's Mac ([release.md](release.md)); no hosted build service
witnesses it. The signature shows who released a file, the SBOM and provenance say what went into it, and the rebuild is
the part an outsider can repeat: for the native libraries it covers, a byte-for-byte match ties the shipped binary to
the tagged sources and the pinned OpenSSL.

## In one command

From a clone of this repository (any commit; the script rebuilds from the tag, not from your checkout):

```
tools/verify/verify-release.sh 0.2.0
```

It downloads every file of every `io.kuicksilver` publication of that version from Maven Central (`repo1.maven.org`)
into `build/verify/<version>/`, then reports one line per check: `OK`, `DIFF`, `SKIPPED` (with the reason) or `FAIL` (a
bad or missing signature, a missing file, a build that failed). It exits 1 on any `DIFF` or `FAIL`. The steps:

1. **Signatures.** Every file (jars, AARs, klibs, POMs, Gradle module files, sources and javadoc jars) must have a good
   `.asc` by the release key, and Central's `.sha1` must match.
2. **SBOM and provenance**, when the GitHub release has them (from 0.2.1): both signed by the release key; every subject
   digest of the provenance equal to the file from Central, no Central file missing from the subjects, and the source
   commit equal to the commit of tag `v<version>`. For 0.2.0 this step is `SKIPPED`: that release has neither.
3. **Rebuild.** The tag `v<version>` must be signed by the release key. Its `tools`, `gradle` and
   `kuicksilver-native/src` are exported with `git archive`, the pinned OpenSSL tarball is downloaded and checked
   (signature and SHA-256, `tools/openssl/fetch.sh` of the tag), and the libraries of [the table
   below](#which-native-libraries-are-reproducible) are built with the tag's own scripts and compared with the copies
   inside the published jar, AAR and klibs.

Options: `--no-rebuild` (steps 1 and 2 only, minutes instead of tens of minutes), `--targets macos-arm64,android-arm64`
(rebuild only those OpenSSL targets), `--rebuilt <dir>` (compare against libraries you built elsewhere),
`--allow-toolchain-drift` (build targets whose Xcode or NDK differs from the pin; a difference is then expected),
`--offline <dir>` (read a local Maven repository instead of Central, see `--help`). It never uploads anything.
`tools/verify/verify-release-test.sh` exercises it on fixtures (a good release, a tampered byte, a signature by another
key, missing files, a library that differs from the rebuild) without network, and the local gate runs it.

## Signatures

The release key is RSA 4096, `Kuicksilver <hello@kuicksilver.io>`, fingerprint

```
22C1 F2E4 FCE9 4B28 EB2C  7DB0 492A BD95 C8D0 EC68
```

It is in this repository as `tools/release/kuicksilver-release-key.asc` and on `keys.openpgp.org` and
`keyserver.ubuntu.com`. Compare the fingerprint from at least two of these sources (and this page as rendered on
GitHub) before trusting it; a check that takes the key from the same place as the artifacts proves little. Release tags
(`git tag -s`) are signed with the same key: `git verify-tag v0.2.0` after importing it.

One file by hand, with the GnuPG you have:

```
gpg --import tools/release/kuicksilver-release-key.asc
gpg --verify kuicksilver-native-jvm-0.2.0.jar.asc kuicksilver-native-jvm-0.2.0.jar   # "Good signature", primary key fingerprint 22C1...EC68
```

`tools/release/verify-signature.sh <file>...` does the same in a throwaway keyring and accepts only a good signature
made by exactly that primary fingerprint.

### In your build: Gradle dependency verification

Gradle can check the signature of every Kuicksilver artifact it resolves. In `gradle/verification-metadata.xml` of your
project, trust the release key for the `io.kuicksilver` group (this repository's own file has the same line):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="https://schema.gradle.org/dependency-verification https://schema.gradle.org/dependency-verification/dependency-verification-1.4.xsd">
   <configuration>
      <verify-metadata>true</verify-metadata>
      <verify-signatures>true</verify-signatures>
      <trusted-keys>
         <trusted-key id="22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68" group="io.kuicksilver"/>
      </trusted-keys>
   </configuration>
   <components/>
</verification-metadata>
```

Gradle then downloads the key on first use (or reads it from `gradle/verification-keyring.keys`, written by
`./gradlew --write-verification-metadata pgp,sha256 --export-keys`) and fails the build when a Kuicksilver artifact is
unsigned or signed by another key. To pin exact files instead of a key, `--write-verification-metadata sha256` writes
a checksum per artifact; you then review the new checksums on every upgrade, which is what pins a version to the bytes
you checked once (for example with the script above).

## SBOM and provenance

From 0.2.1, each GitHub release carries `kuicksilver-<version>-sbom.zip` (CycloneDX 1.6, one document per publication,
with the statically linked OpenSSL and the `ksl` shim as components) and `kuicksilver-<version>.intoto.json` (an in-toto
statement with a SLSA provenance v1 predicate: the source commit, the toolchain and OpenSSL pins, the SHA-256 of every
file of the deployment), each with an `.asc` by the release key. What they contain and how they are made is in
[release.md, Supply chain](release.md#supply-chain-sbom-and-provenance).

`verify-release.sh` checks both signatures and every subject. What the provenance is worth: SLSA Build Level 1. The
same machine and the same person build the artifacts, write the statement and hold the key, so the statement records
what the maintainer says was built; the rebuild is what checks a part of it independently.

## Which native libraries are reproducible

Every published artifact carries native code built from `kuicksilver-native/src/c` (the `ksl` shim) and a static
OpenSSL. The builds hide the checkout path (`-ffile-prefix-map`), fix timestamps (`SOURCE_DATE_EPOCH`, `ZERO_AR_DATE`,
no PE link timestamp), and `tools/check/double-build.sh <target>` builds OpenSSL, `libksl.a`, the prefixed archives and
the JNI library twice from two checkout paths and compares them; the local gate runs it for `macos-arm64` on every
commit. `tools/release/local-release.sh --repro` builds the five JNI libraries and the jar a second time during a
release and compares them (a report, never fatal). Neither compares with a published artifact; `verify-release.sh` does.

| Library | Where it ships | Rebuild host and pinned toolchain | Rebuilt by `verify-release.sh` | 0.2.0 on Maven Central |
|---|---|---|---|---|
| `libksl_<abi>_osx_aarch_64.dylib` | `kuicksilver-native-jvm` jar, `META-INF/native/` | macOS, Xcode of `gradle/toolchains.toml` | yes | identical |
| `libksl_<abi>_osx_x86_64.dylib` | same jar | macOS, same Xcode (cross-built with `-arch x86_64`) | yes | identical |
| `libksl.a`, `libssl.a`, `libcrypto.a` of `macosarm64`, `iosarm64`, `iossimulatorarm64` | `kuicksilver-native-<target>-cinterop-ksl.klib`, `default/targets/<target>/included/` | macOS, Xcode, and the NDK's `llvm-objcopy` (it renames OpenSSL's symbols to `ksl_ossl_`) | yes | identical (all three targets) |
| the same archives of `linuxx64`, `linuxarm64` | the `linuxx64`, `linuxarm64` cinterop klibs | macOS, the Kotlin/Native LLVM and sysroot in `~/.konan/dependencies`, the NDK's `llvm-objcopy` | yes, when those are installed | identical |
| `libksl.so` for `arm64-v8a`, `x86_64`, `armeabi-v7a` | `kuicksilver-native-android` AAR, `jni/<abi>/` | macOS (the release host) with the NDK of `gradle/toolchains.toml` | yes | identical (all three ABIs) |
| `libksl_<abi>_linux_x86_64.so`, `libksl_<abi>_linux_aarch_64.so` | `kuicksilver-native-jvm` jar | the manylinux2014 Docker images of `tools/openssl/docker` | no (`SKIPPED`) | not checked |
| `libksl_<abi>_windows_x86_64.dll` and the `mingwx64` archives | the jar; the `mingwx64` cinterop klib | the mingw-w64 Docker image | no (`SKIPPED`) | not checked |

0.2.0 was checked on 2026-10-22 on an Apple Silicon Mac with Xcode 27.0 and NDK 28.2.13676358 (the pins of its tag):
all 20 files the script rebuilds (the two dylibs, the 15 archives of the five klibs, the three `libksl.so`) are
byte-identical to the ones on Maven Central, and all 351 files carry a good signature by the release key. That run was
on the maintainer's Mac, the machine that built 0.2.0, from a fresh `git archive` of the tag in another directory and
with OpenSSL rebuilt from the verified tarball; it shows the build does not depend on the checkout or on leftover state.
A match on a second, independent machine is what this page asks for and has not been recorded yet; please report
yours, matching or not.

What a match shows: those bytes come from the tag's C sources, the tag's build scripts and the OpenSSL tarball whose
signature and hash were checked, compiled by the pinned toolchain; nothing else was linked in. It does not show that the
toolchain itself is honest (Xcode, the NDK and the Kotlin/Native LLVM are binaries from Apple, Google and JetBrains), and
it says nothing about the files below.

### Not reproducible yet, and why

- **Linux and Windows JNI libraries, `mingwx64` archives.** They are built inside Docker images that
  `tools/openssl/docker` builds locally. The base images are pinned by digest, but the images install packages at build
  time (`yum` on manylinux2014; `apt-get install mingw-w64` on Ubuntu, whose mingw-w64 version is not pinned), so two
  people building the image on different days may get different compilers. The release's image IDs are recorded in the
  provenance, but those images are not published. `verify-release.sh` reports them `SKIPPED`; making them reproducible
  needs published (or fully pinned) build images.
- **Kotlin and Gradle outputs**: class files in the jars, the klib IR and `cstubs.bc` of the cinterop klibs, the AAR's
  classes, POMs, Gradle module files, sources and javadoc jars. Nothing compares them with an independent build today:
  the jars are written with fixed timestamps (Gradle 9 defaults) and `local-release.sh --repro` rebuilds the native jar on
  the same machine, but no tool or record shows that a second machine produces the same bytes. They are covered by the
  signatures and, from 0.2.1, the provenance digests only. You can still rebuild the Kotlin code from the tag and compare
  behaviour, but not bytes.
- **Toolchain drift.** The macOS and iOS libraries depend on the Xcode version (it is written into the Mach-O load
  commands), the Android ones on the NDK. With another Xcode or NDK installed, the script skips those targets unless you
  pass `--allow-toolchain-drift`, and then a `DIFF` is expected, not a finding. The Kotlin/Native LLVM is not pinned in
  `gradle/toolchains.toml`; it is the one the tag's Kotlin version downloads.

## How certificates are verified at run time

Verifying the release proves where the library came from; what it then does with certificates is in
[the TLS guide, Platform trust](guide/tls.md#platform-trust). In short: with `TrustConfig.Platform` the chain goes to the
platform's own verifier (the JDK `X509TrustManager`, the Android `TrustManager` with the app's Network Security Config,
`SecTrust` on Apple, CryptoAPI on Windows, OpenSSL with the system CA bundle on Linux Native), and `ksl` checks the host
name with its own RFC 9525 matcher afterwards on every platform, so a platform can only make the decision stricter. Host
names are always checked; pins are compared against the chain the platform built, never instead of it.

## Reporting a mismatch

A `FAIL` on a signature or a `DIFF` with the pinned toolchain installed is a security report: send it privately as
[SECURITY.md](../SECURITY.md) describes, with the script's output and `build/verify/<version>/logs/`.
