<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releasing

How a version reaches Maven Central. The owner starts it; nothing is released without the owner pressing *Publish*.

The first published version is **0.2.0**. 0.1.0 was a candidate, frozen on 2026-10-09 and never published; no
`v0.1.0` tag or Central deployment exists, and none will.

Since 2026-10-14 a release is built, checked, signed and uploaded **from the owner's Mac** with
`tools/release/local-release.sh`, with no GitHub runner. The `release` workflow below stays as an alternative for later
(the GitHub Actions minutes reset on 2026-11-01); it is not used for 0.2.0.

## Once: accounts, keys, DNS

Done for the project in October 2026, kept here so it can be repeated for a new maintainer.

1. **Central Portal** (central.sonatype.com): an account, the namespace `io.kuicksilver` verified through a TXT record
   on `kuicksilver.io` (the DNS lives at Cloudflare), a *user token* (username + password) for publishing.
2. **Signing key**: an RSA 4096 GPG key for `Kuicksilver <hello@kuicksilver.io>` (id `492ABD95C8D0EC68`), public part
   on `keyserver.ubuntu.com` and `keys.openpgp.org`, private part in a local key ring, never in the repository.
3. **Gradle properties** outside the repository, in `~/.gradle/gradle.properties`:
   ```
   mavenCentralUsername=<token user>
   mavenCentralPassword=<token password>
   signing.keyId=C8D0EC68
   signing.password=<key passphrase>
   signing.secretKeyRingFile=/Users/<you>/.gnupg/kuicksilver-secring.gpg
   ```
   The in-memory form works as well, from the environment: `ORG_GRADLE_PROJECT_signingInMemoryKey`, `…KeyId`,
   `…KeyPassword`, `ORG_GRADLE_PROJECT_mavenCentralUsername`, `…Password` (the workflow takes them from the repository
   secrets `SIGNING_KEY`, `SIGNING_KEY_ID`, `SIGNING_KEY_PASSWORD`, `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`).
   `local-release.sh` checks that they are present and never prints them.
4. **Publishing limits**: Central grants a free organisation 1167 files, 78 MB and 7 releases per month (30 days of
   grace above that); higher limits come after a first publication (Sonatype ticket #128575). A Kuicksilver release is
   seven Kotlin Multiplatform modules with up to nine publications each, plus the BOM; the deployment holds every
   artifact with its `.asc`, `.md5` and `.sha1` (the plugin leaves out `maven-metadata` and checksums of signatures).
   `local-release.sh` counts it from a local publication before every upload and refuses above the limits
   (`--allow-over-limit` within the grace). Size: the `kuicksilver-native` AAR is about 3.6 MB with its three ABIs; the
   `kuicksilver-native` JVM jar carries the five JNI libraries.
5. **Toolchains** of `gradle/toolchains.toml` on the Mac: the pinned NDK (`sdkmanager --install "ndk;<pin>"`) and Xcode
   (`xcode-select -s`); Docker with the `tools/openssl/docker` images (built on first use); the Windows 11 VM in
   Parallels with `~/.kuicksilver-tools/win-jvm-test` for the Windows JVM suites.

## Every release

1. Branch `main`, clean, the full local gate green **on the release commit**:
   ```
   tools/ci/local-matrix.sh --with-interop --with-windows
   ```
   Hours: the CI matrix of `build.yml` on this Mac (Docker for Linux and mingw, the Android emulator running, the
   interop images, the Windows VM). Its last act is the gate record `build/ci/gate/<commit>.stamp`: the commit, the
   options, every step's result, and `result=pass` only when every step passed with the tree clean and on the same
   commit from start to end. Any later commit needs a new run.
2. `CHANGELOG.md`: move `[Unreleased]` under `## [0.2.0] - <date>`; `docs/spec/rfc-compliance.md` and
   `docs/roadmap.md` say what the version does and does not do. Rewrite every sentence marked
   `<!-- release-flip: ... -->` (`grep -rn release-flip README.md docs`) as its comment says, so the README no longer says
   "not on Maven Central yet" and drops the composite-build instructions; the coordinates in the README, the guides and
   `samples/` already name 0.2.0 and need no change. Commit, then run the gate (step 1) on that commit.
3. Dry run, then the release, from the same commit:
   ```
   tools/release/local-release.sh 0.2.0 --dry-run      # everything but the upload; refusals become warnings
   tools/release/local-release.sh 0.2.0                # uploads one deployment, not released
   ```
   The script refuses a malformed or `-SNAPSHOT` version, a branch other than `main` (a detached release commit of
   `main` with `--release-commit <sha>`), a dirty tree, a missing or failed gate record for `HEAD` (or one run with
   `--skip-*`, or without `--with-interop --with-windows`), a `CHANGELOG.md` without the version, an NDK or Xcode other
   than the pins (`--allow-toolchain-drift` to accept), and missing credentials or signing key. Then:
   - OpenSSL: the pinned tarball fetched and verified; `linux-x64`, `linux-arm64` and `mingw-x64` built in Docker (one
     container at a time, under `nice`; `linux-x64` and `mingw-x64` emulated on Apple Silicon), `macos-arm64` and
     `macos-x64` on the host; `no-sslkeylog` checked for each. `mingw-x64` is the `openssl-mingw-x64` the workflow
     downloads.
   - The five JVM libraries, as the CI jobs build them, each into `build/release/jni-artifacts/jni-<classifier>`:
     `osx-aarch_64` and `osx-x86_64` (`.dylib`, the second cross-built with `clang -arch x86_64`), `linux-x86_64` and
     `linux-aarch_64` (manylinux2014 `.so`), `windows-x86_64` (mingw-w64 `.dll`, `tools/ci/jni-windows.sh`). Each is
     checked: architecture, export whitelist (`tools/check/exports.sh`), imported libraries (system ones only), glibc
     floor 2.17 for Linux, the pinned OpenSSL version inside, its `manifest.sha256`.
   - `tools/ci/collect-jni.sh`, the `kuicksilver-native` jar with `-x :kuicksilver-native:buildJniHost`,
     `collect-jni.sh --check-jar` (all five present), each library in the jar equal to the collected one, the jar
     manifest naming the pinned OpenSSL, the ksl ABI and the commit.
   - `publishToMavenLocal` into `build/release/m2` (never `~/.m2`), file count and size per module against the limits.
   - `publishToMavenCentral`: **one Gradle invocation, one deployment** (several would produce several deployments and
     inconsistent root metadata), signed, `automaticRelease = false`:
     ```
     ./gradlew --max-workers=2 -Pkuicksilver.version=0.2.0 -Pkuicksilver.openssl.prebuilt=true \
       -x :kuicksilver-native:buildJniHost publishToMavenCentral
     ```
   Logs: `build/release/logs/<step>.log`. `--resume` reuses the JNI libraries an interrupted run already built and
   checked for the same commit; `--repro` builds them and the jar a second time and compares (a report, never fatal);
   `KSL_GRADLE` names another Gradle launcher.
4. Portal (central.sonatype.com → *Publishing* → *Deployments*): the deployment must read **VALIDATED** (every module,
   every platform publication, the BOM, signatures and checksums). Then press *Publish*. A deployment that fails
   validation is dropped in the portal and the script runs again after the fix; nothing was released.
5. Consumer check from Central (allow the sync to `repo1.maven.org` an hour): `tools/check/consumer-smoke.sh --central
   0.2.0` builds the main source sets of `samples/realtime-telemetry` (JVM and macosArm64) against
   `io.kuicksilver:kuicksilver-quic:0.2.0` and its transitive modules from Maven Central, without `includeBuild` or
   mavenLocal. Its tests are not run there: they need `kuicksilver-testing`, which is not published.
6. Only after the deployment is published: `git tag -s v0.2.0 -m "Kuicksilver 0.2.0"` on the release commit, push `main`
   and the tag, and the GitHub release from the tag with the changelog section. The version is passed to Gradle; it is
   not stored in the tree.

## Alternative: the `release` workflow (not used for 0.2.0)

`.github/workflows/release.yml` does the same on GitHub-hosted runners, once Actions minutes are available again (they
reset on 2026-11-01) and the owner chooses to use them. *Actions → release → Run workflow* on `main` with the version:
the `gate` job refuses a malformed or `-SNAPSHOT` version, another branch, or a commit without a green `build` run (from
a push, the weekly schedule or a manual dispatch; a pull-request run builds the merge commit and does not count);
`publish`, on one macOS runner, downloads that run's `jni-*` and `openssl-mingw-x64` artifacts into `build/` (they live
7 days: re-run `build` first past that), checks every library against its job's `manifest.sha256`, builds and checks the
jar, then runs the `publishToMavenCentral` command above with the credentials and the in-memory signing key from the
repository secrets. Steps 4 to 6 are the same. The `build` workflow is the CI counterpart of `local-matrix.sh` (same
step names, same lists from `tools/ci/matrix.sh`); its `jvm-jar` job fails unless the jar lists all five libraries.

## Checks before publishing

- `-Pkuicksilver.sign=false` publishes unsigned (to count files, or on a machine without the key); a release never uses
  it, and `local-release.sh` refuses when a `gradle.properties` sets it.
- `tools/check/consumer-smoke.sh 0.2.0` builds `samples/realtime-telemetry` from a local publication;
  `KSL_MAVEN_REPO=build/release/m2` points it at the dry run's repository instead of `~/.m2`.
- The published jars and AARs carry `META-INF/LICENSE`, `META-INF/NOTICE` and the OpenSSL license under
  `META-INF/licenses/<module>/`; the native jar's manifest names the OpenSSL version and its SHA-256.
- `./gradlew checkKotlinAbi` is green (part of the gate): the ABI dumps in `*/api/` are the contract of the version.
