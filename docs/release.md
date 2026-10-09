<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releasing

How a version reaches Maven Central. The owner runs it; nothing here is automatic.

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
   CI uses the in-memory form instead: `ORG_GRADLE_PROJECT_signingInMemoryKey`, `…KeyId`, `…KeyPassword`,
   `ORG_GRADLE_PROJECT_mavenCentralUsername`, `…Password`, from the repository secrets `SIGNING_KEY`,
   `SIGNING_KEY_ID`, `SIGNING_KEY_PASSWORD`, `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`.
4. **Publishing limits**: Central grants a free organisation 1167 files, 78 MB and 7 releases per month (30 days of
   grace above that). A Kuicksilver release is seven Kotlin Multiplatform modules with up to nine publications each,
   plus the BOM, each file with `.asc`, `.md5` and `.sha1`: count it with `./gradlew publishToMavenLocal` and
   `find ~/.m2/repository/io/kuicksilver -type f | wc -l` before the first release, and ask
   central-support@sonatype.com for a higher limit if the number is above the quota. Size: the
   `kuicksilver-native` AAR is about 3.6 MB with its three ABIs (armeabi-v7a adds about 1.1 MB compressed, a
   2.2 MB `libksl.so`); the JVM jars carry one JNI library per classifier. Sum the files the same way
   (`du -ch $(find ~/.m2/repository/io/kuicksilver -type f) | tail -1`) against the 78 MB.

## Every release

All targets are published from **one macOS host in one Gradle invocation**: the Apple targets need macOS, Linux and
Windows cross-compile there, and the plugin creates one Central deployment per invocation (several runners would
produce several deployments and inconsistent root metadata).

1. Branch `main`, the full local gate green: `tools/ci/local-matrix.sh --with-interop` (hours; `--skip-android`
   and `--skip-docker` for a quick run) and the GitHub Actions workflow green on the release commit.
2. `CHANGELOG.md`: move `[Unreleased]` under the version and date; `docs/spec/rfc-compliance.md` and `docs/roadmap.md`
   say what the version does and does not do.
3. Tag: `git tag -s v0.1.0 -m "Kuicksilver 0.1.0"`; the version is passed to Gradle, it is not stored in the tree.
4. Publish to the portal without releasing:
   ```
   ./gradlew --max-workers=2 publishToMavenCentral -Pkuicksilver.version=0.1.0
   ```
   Open the deployment in the portal: it must read **VALIDATED** (every module, every platform publication, the BOM,
   signatures and checksums). Then press *Publish*. A deployment that fails validation is dropped in the portal and the
   command runs again after the fix; nothing was released.
5. Consumer check from Central (allow the sync to `repo1.maven.org` an hour): `samples/realtime-telemetry` built against
   `io.kuicksilver:kuicksilver-bom:0.1.0` from `mavenCentral()` only, no `includeBuild`.
6. GitHub release from the tag with the changelog section; push the tag only after the deployment is published.

## Checks before publishing

- `-Pkuicksilver.sign=false` publishes unsigned (to count files, or on a machine without the key); a release never uses it.

- `./gradlew publishToMavenLocal -Pkuicksilver.version=0.1.0` and `samples/realtime-telemetry` built from
  `mavenLocal()` (the CI job `consumer-smoke` does the same).
- The published jars and AARs carry `META-INF/LICENSE`, `META-INF/NOTICE` and the OpenSSL license under
  `META-INF/licenses/<module>/`; the native jar's manifest names the OpenSSL version and its SHA-256.
- `./gradlew checkKotlinAbi` is green: the ABI dumps in `*/api/` are the contract of the version.
