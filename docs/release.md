<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releasing

How a version reaches Maven Central. A maintainer starts it; nothing is released until a maintainer presses *Publish*.

The first published version is **0.2.0**. 0.1.0 was a candidate, frozen on 2026-10-09 and never published; no
`v0.1.0` tag or Central deployment exists, and none will.

Since 2026-10-14 a release is built, checked, signed and uploaded **from a maintainer's Mac** with
`tools/release/local-release.sh`, with no GitHub runner; the gate is `tools/ci/local-matrix.sh` on the same machine.
The GitHub Actions workflows are disabled; the `release` workflow below remains an alternative if hosted CI is enabled.

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
4. **Publishing limits**: Sonatype's default for a free namespace is 1167 files and 78 MB (30 days of grace above
   that). On 2026-10-20 `io.kuicksilver` was granted 7 releases, 100 MB and 2620 files per month. One release is
   1404 files and 49.8 MB, so one release fits in a month, and the project plans at most one release a month. A Kuicksilver release is
   seven Kotlin Multiplatform modules with up to nine publications each, plus the BOM; the deployment holds every
   artifact with its `.asc`, `.md5` and `.sha1` (the plugin leaves out `maven-metadata` and checksums of signatures).
   `local-release.sh` counts it from a local publication before every upload and refuses above the limits
   (`--allow-over-limit` within the grace); its defaults are Sonatype's (`KSL_CENTRAL_MAX_FILES=1167`,
   `KSL_CENTRAL_MAX_BYTES=78000000`), so set the namespace's limits there (2620 files, 100000000 bytes). Size: the `kuicksilver-native` AAR is about 3.6 MB with its three ABIs; the
   `kuicksilver-native` JVM jar carries the five JNI libraries.
5. **Toolchains** of `gradle/toolchains.toml` on the Mac: the pinned NDK (`sdkmanager --install "ndk;<pin>"`) and Xcode
   (`xcode-select -s`); Docker with the `tools/openssl/docker` images (built on first use); a Windows 11 VM (Parallels)
   and a runner for it, named by `KSL_WIN_JVM_TEST`, for the Windows JVM suites. The runner is a maintainer-local script,
   not in the repository: it runs the JVM suites of the given tree (`-w <root>`) in the VM against the mingw-w64 dll and
   ends its output with a `== summary` block of tests, failures and errors per module, which
   `tools/ci/local-matrix.sh --with-windows` reads (no tests run, or any failure, fails the step).

## Every release

1. Branch `main` (or the version's maintenance branch, see [below](#releasing-from-a-maintenance-branch)), clean, the
   full local gate green **on the release commit**:
   ```
   tools/ci/local-matrix.sh --with-interop --with-windows
   ```
   Hours: the steps of `build.yml`'s matrix on this Mac (Docker for Linux and mingw, the Android emulator running, the
   interop images, the Windows VM). Its last act is the gate record `build/ci/gate/<commit>.stamp`: the commit, the
   options, every step's result, and `result=pass` only when every step passed with the tree clean and on the same
   commit from start to end. Any later commit needs a new run.
2. The release commit. `CHANGELOG.md`: move `[Unreleased]` (or the branch's `## [<version>] - unreleased`) under
   `## [<version>] - <date>`; `docs/spec/rfc-compliance.md` and `docs/roadmap.md` say what the version does and does not
   do. The version in the tree: every Gradle and sample fallback names `<X.Y.Z>-SNAPSHOT` of the version
   (`kuicksilver.kmp.gradle.kts`, `kuicksilver.release.gradle.kts`, `kuicksilver-bom`, the three sample builds,
   `KuicksilverInfo.VERSION` in `samples/ios/kuicksilver-swift`, `tools/check/consumer-smoke.sh`), normally set when the
   line was started, and for a final version the README ("X.Y.Z is on Maven Central", the dependency line) and
   `docs/guide/ios.md` (the dependency line, the xcframework URL) name the version itself (a prerelease such as
   0.3.0-rc1 leaves them at the last final version and needs only the `0.3.0-SNAPSHOT` fallbacks). Commit, then run the gate
   (step 1) on that commit.
3. Dry run, then the release, from the same commit:
   ```
   tools/release/local-release.sh <version> --dry-run      # everything but the upload; refusals become warnings
   tools/release/local-release.sh <version>                # uploads one deployment, not released
   ```
   The script refuses a malformed or `-SNAPSHOT` version, a branch other than `main` or the version's own
   `release/<X.Y>.x` (a detached release commit of either with `--release-commit <sha>`), `main` once `release/<X.Y>.x`
   exists (locally or on origin: a release fetches origin first, a dry run uses what was fetched last), a branch behind
   its `origin` counterpart (pull first; a `--release-commit` may be older on purpose), a version already on Maven
   Central (a release asks `repo1.maven.org` for the BOM's POM and refuses on 200, or when it gets no 200 or 404; a dry
   run does not ask), a tree whose version fallbacks or (final versions) README and iOS
   guide coordinates do not name the version (step 2), a dirty tree, a missing or failed gate record for `HEAD` (or one run with
   `--skip-*`, or without `--with-interop --with-windows`), a `CHANGELOG.md` without the version and its date (`## [0.2.0] - 2026-10-18`), an NDK or Xcode other
   than the pins (`--allow-toolchain-drift` to accept), and missing credentials or signing key
   (`tools/release/local-release-test.sh` runs the branch, origin, Central, CHANGELOG and version refusals in a
   throwaway repository with a stubbed Central, and the version checks on the repository's own files; the local gate
   runs it). Then:
   - OpenSSL: the pinned tarball fetched and verified; **all twelve targets rebuilt from it** (`KSL_OPENSSL_FRESH=1`:
     `build/openssl` (each worktree has its own) and the build cache are deleted or bypassed, never reused):
     `linux-x64`, `linux-arm64` and `mingw-x64` in Docker (one container at a time, under `nice`; `linux-x64` and
     `mingw-x64` emulated on Apple Silicon), `macos-arm64`, `macos-x64`, `ios-arm64`, `ios-sim-arm64`, the three Android
     ABIs and the two Kotlin/Native Linux targets on the host; `no-sslkeylog` and the absence of the FIPS provider
     (`tools/check/openssl-no-fips.sh`) checked for each. Each build writes
     `provenance.txt` (the tarball's SHA-256, the configure line, the archives' SHA-256), which
     `-Pkuicksilver.openssl.prebuilt=true` checks before Gradle reuses the build (`tools/openssl/prebuilt-test.sh` runs
     its negative controls). `mingw-x64` is the `openssl-mingw-x64` the workflow downloads.
   - The five JVM libraries, as `build.yml`'s jobs build them, each into `build/release/jni-artifacts/jni-<classifier>`:
     `osx-aarch_64` and `osx-x86_64` (`.dylib`, the second cross-built with `clang -arch x86_64`), `linux-x86_64` and
     `linux-aarch_64` (manylinux2014 `.so`), `windows-x86_64` (mingw-w64 `.dll`, `tools/ci/jni-windows.sh`). Each is
     checked: architecture, export whitelist (`tools/check/exports.sh`), imported libraries (system ones only), glibc
     floor 2.17 for Linux, the pinned OpenSSL version inside, no sanitizer or coverage instrumentation and no debug
     sections (`tools/check/native-release.sh`), its `manifest.sha256`.
   - `tools/ci/collect-jni.sh`, the `kuicksilver-native` jar with `-x :kuicksilver-native:buildJniHost`,
     `collect-jni.sh --check-jar` (all five present), each library in the jar equal to the collected one, the jar
     manifest naming the pinned OpenSSL, the ksl ABI and the commit.
   - `publishToMavenLocal` into `build/release/m2` (never `~/.m2`), file count and size per module against the limits.
     The published AAR's three `libksl.so` and the static archives in each Kotlin/Native `cinterop-ksl` klib get the
     same checks as the JVM libraries (`tools/check/native-release.sh`: the pinned OpenSSL inside, no instrumentation or
     debug sections, the export whitelist for the `.so`, the `ksl_` prefix for the archives).
   - The supply-chain files of [Supply chain](#supply-chain-sbom-and-provenance), for the GitHub release and not for
     Central: `build/release/kuicksilver-<version>-sbom.zip` (the CycloneDX SBOM of every publication, checked against
     the CycloneDX 1.6 schema) and `build/release/kuicksilver-<version>.intoto.json` (the build provenance), each signed
     with the release key (`.asc`) and the signature checked. A dry run without a key leaves them unsigned.
   - `publishToMavenCentral`: **one Gradle invocation, one deployment** (several would produce several deployments and
     inconsistent root metadata), signed, `automaticRelease = false`:
     ```
     ./gradlew --max-workers=2 -Pkuicksilver.version=<version> -Pkuicksilver.openssl.prebuilt=true \
       -x :kuicksilver-native:buildJniHost publishToMavenCentral
     ```
   Logs: `build/release/logs/<step>.log`. `--resume` reuses the JNI libraries an interrupted run already built and
   checked for the same commit; `--repro` builds them and the jar a second time and compares (a report, never fatal);
   `KSL_GRADLE` names another Gradle launcher.
4. Portal (central.sonatype.com → *Publishing* → *Deployments*): the deployment must read **VALIDATED** (every module,
   every platform publication, the BOM, signatures and checksums). Then press *Publish*. A deployment that fails
   validation is dropped in the portal and the script runs again after the fix; nothing was released.
5. Consumer check from Central (allow the sync to `repo1.maven.org` an hour): `tools/check/consumer-smoke.sh --central
   <version>` builds the main source sets of `samples/realtime-telemetry` (JVM and macosArm64) against
   `io.kuicksilver:kuicksilver-quic:<version>` and its transitive modules from Maven Central, without `includeBuild` or
   mavenLocal. Its tests are not run there: they need `kuicksilver-testing`, which is not published.
6. Only after the deployment is published: `git tag -s v<version> -m "Kuicksilver <version>"` on the release commit, push the
   branch it was released from (`main` or `release/<X.Y>.x`; the script's last lines name it) and the tag, and the GitHub release from the tag with the changelog section. Attach the four supply-chain files of
   step 3: `kuicksilver-<version>-sbom.zip`, `kuicksilver-<version>.intoto.json` and their `.asc`. The version is passed to
   Gradle (`-Pkuicksilver.version`); the tree's `-SNAPSHOT` fallbacks only name the line, and the script checks that they
   do.
7. Context7 (the documentation index coding agents read, configured by `context7.json` at the root): add the new tag to
   `previousVersions`, and point `branch` at the branch whose docs describe the newest published version (it must
   not name a branch with unreleased API). The index refreshes from GitHub; nothing is uploaded.

## Releasing from a maintenance branch

Patch releases of a published line come from `release/<X.Y>.x` (`release/0.2.x` for 0.2.1, 0.2.2, ...) while `main`
moves on to the next minor version. `local-release.sh` accepts that branch only for versions of its own X.Y (0.2.1 from
`release/0.2.x`, not 0.3.0), and once the branch exists it refuses that X.Y from `main` (0.2.1 from `main` would ship
0.3.0-line code as 0.2.1); it names the branch in its "not on origin" note and in the push of step 6. A further patch
(0.2.2) needs its own preparing commit on the branch first: the fallbacks to `0.2.2-SNAPSHOT`, the README and the iOS
guide to 0.2.2, `## [0.2.2] - unreleased` in the CHANGELOG; the script refuses the release until they say so.

- **Create it** from `main` at the commit the patch line starts from: `git branch release/0.2.x <commit>` (or from the
  previous release tag when `main` already holds work that must not ship in the patch).
- **Fixes land on `main` first**, reviewed there, and are cherry-picked to the branch (`git cherry-pick -x <sha>`, which
  records the origin). A fix that only applies to the branch (the code it fixes is gone from `main`) is made there, and
  the test that proves it is ported to `main` if the behaviour still exists. Nothing is merged from `main` into the
  branch.
- **CHANGELOG**: entries are written under `[Unreleased]` on `main` as usual and come to the branch with their fixes.
  On the branch, what the patch ships moves under `## [0.2.1] - unreleased` as soon as the branch is made; the script
  refuses that placeholder, and the release commit replaces it with the date (steps 2 and 3 run there, with the gate on
  that commit: a gate on an earlier commit of the branch does not count for it). After the release, the same section goes to `main` (cherry-pick the release commit, or
  edit by hand), so `main`'s `[Unreleased]` keeps only what is not yet released. Version coordinates in the README and
  the guides follow the newest published version on both branches.
- `context7.json` (step 7) points at the branch whose docs describe the newest published version; for a patch release
  of the newest line that is the maintenance branch until the next minor version is released from `main`.

## Supply chain: SBOM and provenance

From 0.2.1 every release has a CycloneDX SBOM and a build provenance statement, both made by `local-release.sh` (dry run
included) and attached to the GitHub release. Neither goes to Maven Central.

### SBOM

`./gradlew sbomZip` (the root plugin `kuicksilver.release`) runs `cyclonedxSbom` in every published module
(`build-logic/src/main/kotlin/Sbom.kt`, `SbomWiring.kt`) and writes one CycloneDX 1.6 JSON document per publication,
`<artifactId>-<version>.cdx.json`, 64 for 0.2.x:

- each platform publication (`-jvm`, `-android`, `-iosarm64`, ...) from the resolved graph of the configuration its
  consumers get (`jvmRuntimeClasspath`, `androidRuntimeClasspath`, `<target>CompileKlibraries`): every component with
  its package URL, the SHA-256 of the external artifacts Gradle downloaded (already checked by dependency verification),
  and the dependency graph. The Kuicksilver modules carry no hash there; their digests are in the provenance;
- the root publication of each module (`kuicksilver-quic`, ...) aggregating its platform publications, and the BOM
  listing the seven modules;
- what Gradle cannot see: the `ksl` C shim (its ABI version, the commit) and **OpenSSL** (version, tarball SHA-256,
  download URL, CPE `cpe:2.3:a:openssl:openssl:<version>`, the configure flags, `fips-provider: not built`), statically
  linked, under every publication that embeds `kuicksilver-native` or depends on it. Values come from
  `gradle/openssl.toml`, `tools/openssl/configure-flags.txt` and `ksl.h`; the timestamp is the commit's, so the same commit
  gives the same documents.

`validateSbom` checks every document against the CycloneDX 1.6 JSON schema with
[cyclonedx-core-java](https://github.com/CycloneDX/cyclonedx-core-java), the reference library that carries the schema;
it is a library in an isolated class loader, not a Gradle plugin, and is verified like every dependency
(`gradle/verification-metadata.xml`: by signature for cyclonedx-core-java, json-schema-validator, itu, stax2-api,
packageurl-java and snakeyaml, each new key trusted for that one version only; by checksum for the junit-bom 6.1.3 POM,
signed by a JUnit key the file already lists as ignored). No third-party
SBOM plugin is used: the CycloneDX Gradle plugin makes one document per Gradle project, not per publication, and cannot
add the statically linked OpenSSL.

**GitHub release, not Central.** Decided 2026-10-20 for 0.2.1, on this evidence:

- What libraries do. On Maven Central (checked 2026-10-20) none of ktor 3.6.0, OkHttp 5.5.0, Netty 4.2.19.Final,
  netty-tcnative 2.0.84.Final, kotlinx-coroutines 1.11.0, kotlinx-io 0.9.1, gRPC 1.85.0, Conscrypt 2.7.0, Bouncy Castle
  1.86, Jetty 12.1.14, Tomcat 11.0.27 or Spring 7.1.0-M2 publishes an SBOM next to its artifacts. Those that do are
  single-artifact Maven builds with the CycloneDX Maven plugin in their parent POM: Apache Commons Lang 3.21.0
  (`-cyclonedx.json`, `-cyclonedx.xml`, `.spdx.json`), Log4j (`-cyclonedx.xml`), Jackson 2.22.4
  (`-sbom-cyclonedx.json`, `-sbom-cyclonedx.xml`). No Kotlin Multiplatform library we know of does.
- What Central accepts. A file with a classifier (`<artifactId>-<version>-cyclonedx.json`) is an ordinary artifact to
  the portal; it validates with its `.asc`, `.md5` and `.sha1`. So each SBOM file costs **4 files** of the deployment.
- The limit. The 0.2.0 deployment was 1404 files against Sonatype's default of 1167 (30 days of grace while Sonatype
  reviewed the limits; since the grant of 2026-10-20 the namespace has 2620 files per month, which still leaves room
  for only one release a month).
  On Central the SBOMs would add: JSON per publication 64 × 4 = **256** (1660 files); JSON and XML per publication
  **512** (1916); JSON on the eight root publications only **32** (1436); JSON and XML there **64** (1468). Any of these
  grows a deployment that is already over the limit. On the GitHub release they cost **0** Central files; the count of
  step 5 is unchanged.

Revisit when Central raises the limit: the cheapest useful form is one `-cyclonedx.json` on each root publication (the
aggregate document, 32 files), which tools that read SBOMs from Maven coordinates can find.

### Build provenance

`tools/release/provenance.py` writes `kuicksilver-<version>.intoto.json`: an [in-toto Statement
v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) with a [SLSA provenance
v1](https://slsa.dev/spec/v1.0/provenance) predicate.

- `subject`: the SHA-256 of every file of the local publication that the deployment uploads (jars, AARs, klibs, POMs,
  Gradle module files, sources and javadoc jars; not the `.asc`, `.md5`, `.sha1`), under its repository path
  (`io/kuicksilver/<artifactId>/<version>/<file>`), plus the SBOM archive.
- `buildDefinition`: the source (repository and commit), the version and the command line; the toolchain pins of
  `gradle/toolchains.toml`, the OpenSSL pin of `gradle/openssl.toml`, the Kotlin version, and what the Mac actually
  had (macOS, Xcode, NDK, Docker); the local gate record; as `resolvedDependencies` the commit, the OpenSSL tarball
  (SHA-256, signing key fingerprint, the configure flags as the SBOM lists them, their file and its SHA-256), the
  Gradle distribution (its SHA-256 from the wrapper properties), `verification-metadata.xml`, the version catalog, the
  Windows JDK and the local Docker images.
- `runDetails`: the builder (this document, the maintainer's workstation), start and end, and as byproducts the five JNI
  libraries and the `libcrypto.a`/`libssl.a` of all twelve OpenSSL targets.

It is signed like the Maven artifacts: Gradle's signing plugin with the same key properties (`signReleaseFiles`),
a detached armored `.asc`. `tools/release/verify-signature.sh <file>...` checks a signature against the release key
(`22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68`, in `tools/release/kuicksilver-release-key.asc`, the key
`gradle/verification-metadata.xml` trusts for `io.kuicksilver`); `local-release.sh` runs it after
signing. A user checks a release the same way, then compares the subjects with the files from Central:

```
tools/release/verify-signature.sh kuicksilver-0.2.1.intoto.json kuicksilver-0.2.1-sbom.zip
python3 -c 'import json,sys; [print(s["digest"]["sha256"]+"  "+s["name"]) for s in json.load(open(sys.argv[1]))["subject"]]' \
  kuicksilver-0.2.1.intoto.json > sums.txt     # then, in a mirror of the io/kuicksilver paths: shasum -a 256 -c sums.txt
```

**What this is worth.** This is **SLSA Build Level 1**: provenance exists and says how the artifacts were built, from
which source, with which inputs. It is not Level 2, which needs a hosted build platform that generates and signs the
provenance itself; here the same Mac and the same person build the artifacts, write the statement and hold the key, so
the signature shows who released it, not that the build followed the statement. It is not Level 3 (isolated,
ephemeral builds; signing material out of reach of the build) either. The statement is a plain signed JSON file, not a
DSSE envelope, so `slsa-verifier` does not read it. Two further limits: the subjects are the files of the local
publication, and the upload is a second Gradle invocation on the same commit and outputs (up to date, so identical
files; the `.asc` signatures are not covered); and nothing third-party witnesses the build, which is what the
`release` workflow below could add once it is used (GitHub's artifact attestations, SLSA Build L2).

## Alternative: the `release` workflow (disabled)

`.github/workflows/release.yml` does the same on GitHub-hosted runners. The workflows are disabled; this is the
alternative if hosted CI is enabled. *Actions → release → Run workflow* on `main` with the version:
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
- `tools/check/consumer-smoke.sh <version>` builds `samples/realtime-telemetry` from a local publication;
  `KSL_MAVEN_REPO=build/release/m2` points it at the dry run's repository instead of `~/.m2`.
- The published jars and AARs carry `META-INF/LICENSE`, `META-INF/NOTICE` and the OpenSSL license under
  `META-INF/licenses/<module>/`; the native jar's manifest names the OpenSSL version and its SHA-256.
- `./gradlew checkKotlinAbi` is green (part of the gate): the ABI dumps in `*/api/` are the contract of the version.
