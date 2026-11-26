#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The branch, origin, Maven Central, CHANGELOG and version refusals of tools/release/local-release.sh (step 1), in a
# throwaway repository with main, maintenance branches, a feature branch and a local bare origin: the script runs as
# committed up to its local-gate check, where a stub line stops it (nothing is built, signed or uploaded). Maven Central is
# a stub (KSL_CENTRAL_PROBE) and a curl that fails on PATH, so no case reaches the network. Each case expects "ok" or
# "refuse", optionally with a pattern its output must contain; a last case runs the version checks on the repository's own
# version files. Usage: local-release-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
tmp=$(mktemp -d)
# git and gpg of their own: never the maintainer's global git identity or keyring. The global identity is someone else
# on purpose (the Swift package must carry the release identity anyway); a throwaway signing key stands in for the release
# key, and a second one for a wrong key (a short directory: macOS limits gpg-agent socket paths)
gpgh=$(mktemp -d /tmp/ksl-gpgt.XXXXXX); chmod 700 "$gpgh"
trap 'gpgconf --homedir "$gpgh" --kill all >/dev/null 2>&1; rm -rf "$tmp" "$gpgh"' EXIT
export GNUPGHOME="$gpgh" GIT_CONFIG_GLOBAL="$tmp/global.gitconfig" GIT_CONFIG_NOSYSTEM=1
for k in release other; do
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "Test $k <$k@example.invalid>" ed25519 sign never >/dev/null 2>&1 \
    || { echo "FAIL: test signing key"; exit 2; }
done
FPR=$(gpg --batch --with-colons --list-keys release@example.invalid 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')
OTHER_FPR=$(gpg --batch --with-colons --list-keys other@example.invalid 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')
gpg --batch --armor --export "$FPR" > "$tmp/test-release-key.asc"
export KSL_SWIFT_TAG_KEY="$tmp/test-release-key.asc" KSL_SWIFT_TAG_FPR="$FPR" KSL_RELEASE_KEY_FILE="$tmp/test-release-key.asc" KSL_RELEASE_FPR="$FPR" KSL_HOOK_TEST=1
printf '[user]\n\tname = Global Person\n\temail = global@example.invalid\n\tsigningkey = %s\n[gpg]\n\tprogram = gpg\n' "$FPR" > "$GIT_CONFIG_GLOBAL"
# Maven Central: 0.2.0 is published, nothing else; KSL_CENTRAL_STATUS forces an answer (000: no answer)
mkdir -p "$tmp/bin"
printf '#!/bin/sh\nif [ -n "${KSL_CENTRAL_STATUS:-}" ]; then echo "$KSL_CENTRAL_STATUS"; exit 0; fi\ncase "$1" in */kuicksilver-bom/0.2.0/kuicksilver-bom-0.2.0.pom) echo 200 ;; *) echo 404 ;; esac\n' > "$tmp/bin/central"
printf '#!/bin/sh\necho "curl called in a test: $*" >&2; exit 7\n' > "$tmp/bin/curl"
chmod +x "$tmp/bin/central" "$tmp/bin/curl"
export KSL_CENTRAL_PROBE="$tmp/bin/central" PATH="$tmp/bin:$PATH"
# the Swift package repository: empty (no version released there yet); swift-tagged.git already has 0.2.1 and 0.4.0-rc1
for r in swift swift-tagged; do git init -q --bare -b main "$tmp/$r.git"; done
( w="$tmp/swift-w"; git init -q -b main "$w" && cd "$w" && git -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m x \
  && git tag 0.2.1 && git tag 0.4.0-rc1 && git push -q "$tmp/swift-tagged.git" main 0.2.1 0.4.0-rc1 ) || { echo "FAIL: Swift package fixture"; exit 2; }
export KSL_SWIFT_REPO="$tmp/swift.git"
marker='^# the local gate: tools/ci/local-matrix.sh writes'
grep -qE "$marker" "$root/tools/release/local-release.sh" || { echo "FAIL: the local-gate marker line is gone from local-release.sh"; exit 2; }
new_repo() { # <dir>: a repository with what the script reads before the gate, and the script stopped there
  git init -q -b main "$1"; cd "$1" || exit 2
  git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false; git config core.hooksPath /dev/null
  mkdir -p tools/release tools/check kuicksilver-native/src/c gradle
  cp "$root/tools/check/llvm-tool.sh" tools/check/
  cp "$root/tools/clean-build-env.sh" tools/
  cp "$root/kuicksilver-native/src/c/ksl.h" kuicksilver-native/src/c/; cp "$root/gradle/openssl.toml" gradle/
  mkdir -p tools/release/swift-package licenses; cp "$root/tools/release/swift-package.sh" tools/release/
  cp "$root"/tools/release/swift-package/*.in tools/release/swift-package/; cp "$root/LICENSE" "$root/NOTICE" .
  cp "$root"/licenses/LICENSE.openssl.txt "$root"/licenses/LICENSE.zlib.txt "$root"/licenses/LICENSE.brotli.txt licenses/
  awk -v m="$marker" '$0 ~ m {print "echo \"STOPPED-BEFORE-GATE push_branch=$push_branch problems=$problems\"; exit 0"} {print}' \
    "$root/tools/release/local-release.sh" > tools/release/local-release.sh
  printf 'build/\n' > .gitignore
}
git init -q --bare "$tmp/origin.git"; new_repo "$tmp/repo"

tree_version() { # <X.Y.Z of every -SNAPSHOT fallback> <version the README, docs/install.md and the iOS guide name> [<file to leave behind>]
  local s="$1-SNAPSHOT" p="$2" f
  for f in build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts build-logic/src/main/kotlin/kuicksilver.release.gradle.kts \
      kuicksilver-bom/build.gradle.kts samples/realtime-telemetry/build.gradle.kts samples/ios/shared/build.gradle.kts \
      samples/ios/kuicksilver-swift/build.gradle.kts samples/compose-demo/build.gradle.kts samples/kq-cli/build.gradle.kts; do
    [ "$f" = "${3:-}" ] && continue
    mkdir -p "$(dirname "$f")"; printf 'version = providers.gradleProperty("kuicksilver.version").getOrElse("%s")\n' "$s" > "$f"
  done
  printf 'version="${1:-%s}"\n' "$s" > tools/check/consumer-smoke.sh
  mkdir -p docs/guide
  printf '> The API can change between any two 0.x releases, and %s is on Maven Central.\n\n    implementation("io.kuicksilver:kuicksilver-ktor-client:%s")\n' "$p" "$p" > README.md
  printf '    implementation(platform("io.kuicksilver:kuicksilver-bom:%s"))\n.package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "%s")),\n' "$p" "$p" > docs/install.md
  printf '    implementation(platform("io.kuicksilver:kuicksilver-bom:%s"))\n' "$p" > docs/guide/quickstart.md
  printf '        implementation("io.kuicksilver:kuicksilver-http3:%s")   // or -quic\n    .package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "%s")),\n            url: "https://github.com/kuicksilver/kuicksilver/releases/download/v%s/Kuicksilver.xcframework.zip",\n' "$p" "$p" "$p" > docs/guide/ios.md
}
commit() { git add -A; git commit -qm "$1"; }

# base: the 0.2.1 line prepared (the fork point of release/0.2.x); main then moves to 0.3.0
printf '# Changelog\n\n## [0.15.0] - 2028-01-01\n\n## [0.14.0] - 2027-12-01\n\n## [0.13.0] - 2027-11-01\n\n## [0.12.0] - 2027-10-01\n\n## [0.11.0] - 2027-09-01\n\n## [0.10.0] - 2027-08-01\n\n## [0.9.0] - 2027-07-01\n\n## [0.8.0] - 2027-06-01\n\n## [0.7.0] - 2027-05-01\n\n## [0.6.0] - 2027-04-01\n\n## [0.5.0] - 2027-03-01\n\n## [0.4.0-rc1] - 2027-02-01\n\n## [0.3.1] - 2027-01-15\n\n## [0.3.0] - 2026-12-01\n\n## [0.2.2] - 2026-11-25\n\n## [0.2.2-rc1] - 2026-11-20\n\n## [0.2.1] - 2026-11-03\n\n## [1.2.1] - 2027-01-01\n\n## [0.2.9] - unreleased\n\n## [0.2.8]\n' > CHANGELOG.md
tree_version 0.2.1 0.2.1; commit base
git remote add origin "$tmp/origin.git"; git push -q origin main
git branch release/0.2.x
tree_version 0.3.0 0.3.0; commit "main: prepare 0.3.0"
git checkout -q release/0.2.x; echo c > h; commit branch-only; git checkout -q main
git branch release/0.1.x main
git checkout -q -b feature main; echo z > z; commit feature-only
git checkout -q -b release/0.4.x main; tree_version 0.4.0 0.3.0; commit "0.4 line"   # a prerelease leaves the coordinates alone
git checkout -q -b release/0.5.x main; tree_version 0.5.0 0.3.0; commit "0.5 line, README not moved"
git checkout -q -b release/0.6.x main; tree_version 0.6.0 0.6.0; printf '        implementation("io.kuicksilver:kuicksilver-http3:0.3.0")\n' > docs/guide/ios.md; commit "0.6 line, iOS guide not moved"
git checkout -q -b release/0.7.x main; tree_version 0.7.0 0.7.0; printf 'version = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")\n' > kuicksilver-bom/build.gradle.kts; commit "0.7 line, BOM not moved"
git checkout -q -b release/0.8.x main; tree_version 0.8.0 0.8.0 kuicksilver-bom/build.gradle.kts; git rm -q kuicksilver-bom/build.gradle.kts; commit "0.8 line, no BOM fallback"
git checkout -q -b release/0.9.x main; tree_version 0.9.0 0.9.0; printf '> This README describes 0.9.0, the release in preparation.\n' >> README.md; commit "0.9 line, README still says in preparation"
git checkout -q -b release/0.10.x main; tree_version 0.10.0 0.10.0; printf 'Until 0.10.0 is on Maven Central, build it from a checkout.\n' >> README.md; commit "0.10 line, README still has the build-it-yourself note"
git checkout -q -b release/0.11.x main; tree_version 0.11.0 0.11.0; printf '    implementation(platform("io.kuicksilver:kuicksilver-bom:0.3.0"))\n' >> docs/install.md; commit "0.11 line, a block of docs/install.md not moved"
git checkout -q -b release/0.12.x main; tree_version 0.12.0 0.12.0; printf '**Until 0.12.0 is on Maven Central**, build it from a checkout of main.\n' >> docs/install.md; commit "0.12 line, docs/install.md still has the build-it-yourself note"
git checkout -q -b release/0.13.x main; tree_version 0.13.0 0.13.0; rm docs/install.md; commit "0.13 line, docs/install.md missing"
git checkout -q -b release/0.14.x main; tree_version 0.14.0 0.14.0; printf '.package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "0.3.0")),\n' >> docs/install.md; commit "0.14 line, SwiftPM line in docs/install.md not moved"
git checkout -q -b release/0.15.x main; tree_version 0.15.0 0.15.0; printf '    .package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "0.3.0")),\n' >> docs/guide/ios.md; commit "0.15 line, SwiftPM line in the iOS guide not moved"
git checkout -q main

pass=0; fail=0
T_ENV=()   # VAR=value words for local-release.sh alone (not for t's git); see negative_releaseClearsBuildEnvironment
t() { # <label> <ok|refuse>[:<pattern in the output>] <checkout target> <args...>
  local label="$1" exp="${2%%:*}" pat="" tgt="$3"; [ "$2" = "${2#*:}" ] || pat="${2#*:}"; shift 3
  git checkout -q $tgt || { echo "FAIL: checkout $tgt"; exit 2; }
  local out rc got verdict
  out=$( [ -z "${T_ENV[*]:-}" ] || export "${T_ENV[@]}"; bash tools/release/local-release.sh "$@" 2>&1); rc=$?
  got=$([ $rc = 0 ] && echo ok || echo refuse)
  verdict=FAIL; if [ "$got" = "$exp" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<< "$out"; }; then verdict=ok; fi
  [ $verdict = ok ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-4s %-58s exp=%-6s got=%-6s | %s\n' "$verdict" "$label" "$exp" "$got" \
    "$(grep -E 'REFUSED|WARN|STOPPED|note' <<< "$out" | sed 's/^ *//' | tr '\n' ' ' | cut -c1-230)"
}
M=$(git rev-parse main); B=$(git rev-parse release/0.2.x); BASE=$(git rev-parse main~1); F=$(git rev-parse feature)

# branches
t "main, 0.3.0"                                          ok:push_branch=main            main 0.3.0
t "main, 0.2.1 while release/0.2.x exists"               "refuse:release/0.2.x exists"  main 0.2.1
t "main, 0.3.1 (no release/0.3.x, tree is 0.3.0)"        "refuse:0.3.0-SNAPSHOT"        main 0.3.1
t "release/0.2.x, 0.2.1"                                 ok:push_branch=release/0.2.x   release/0.2.x 0.2.1
t "release/0.2.x, 0.2.2 without the version bump"        "refuse:0.2.1-SNAPSHOT"        release/0.2.x 0.2.2
t "release/0.2.x, 0.2.2-rc1 without the version bump"    "refuse:0.2.1-SNAPSHOT"        release/0.2.x 0.2.2-rc1 --central-prerelease
t "release/0.4.x, 0.4.0-rc1 (coordinates not checked)"   ok:push_branch=release/0.4.x   release/0.4.x 0.4.0-rc1 --central-prerelease
# the environment that would change a native build is unset before anything else (tools/clean-build-env.sh). It reaches
# local-release.sh only (T_ENV), never t's git: with an SDKROOT that does not exist, macOS's /usr/bin tool shims (git among
# them) ask xcodebuild for that SDK, fail, and open the "install the command line developer tools" dialog
T_ENV=(CCC_OVERRIDE_OPTIONS="+-include/nonexistent/probe.h" CPATH=/nonexistent SDKROOT=/nonexistent OPT=-O0 CFLAGS=-O0)
t "negative_releaseClearsBuildEnvironment"               "ok:note: CCC_OVERRIDE_OPTIONS is ignored" main 0.3.0
T_ENV=()
# a prerelease goes to Central only when asked for (its quota), never by default
t "negative_prereleaseWithoutMode"                       "refuse:is a prerelease: --github-prerelease" release/0.4.x 0.4.0-rc1
t "negative_prereleaseWithoutModeDryRun"                 "refuse:is a prerelease: --github-prerelease" release/0.4.x 0.4.0-rc1 --dry-run
t "negative_centralPrereleaseFinalVersion"               "refuse:--central-prerelease takes a prerelease" release/0.2.x 0.2.1 --central-prerelease
t "negative_bothPrereleaseModes"                         "refuse:exclude each other"    release/0.4.x 0.4.0-rc1 --github-prerelease --central-prerelease
t "release/0.2.x, 0.3.0"                                 "refuse:maintenance branch of" release/0.2.x 0.3.0
t "release/0.2.x, 1.2.1"                                 "refuse:maintenance branch of" release/0.2.x 1.2.1
t "release/0.1.x, 0.2.1"                                 "refuse:maintenance branch of" release/0.1.x 0.2.1
t "feature, 0.2.1"                                       "refuse:not main or"           feature 0.2.1
# --release-commit
t "detached main tip, no --release-commit"               refuse                         "--detach $M" 0.3.0
t "--release-commit main tip, 0.3.0"                     ok:push_branch=main            "--detach $M" 0.3.0 --release-commit $M
t "--release-commit release/0.2.x tip, 0.2.1"            ok:push_branch=release/0.2.x   "--detach $B" 0.2.1 --release-commit $B
t "--release-commit release/0.2.x tip, 0.3.0"            refuse                         "--detach $B" 0.3.0 --release-commit $B
t "--release-commit fork point (both), 0.2.1"            ok:push_branch=release/0.2.x   "--detach $BASE" 0.2.1 --release-commit $BASE
t "--release-commit main-only commit, 0.2.1"             "refuse:not on release/0.2.x"  "--detach $M" 0.2.1 --release-commit $M
t "--release-commit not HEAD"                            refuse                         "--detach $B" 0.2.1 --release-commit $M
t "--release-commit on release/0.2.x checkout"           ok                             release/0.2.x 0.2.1 --release-commit $B
t "--release-commit feature-only commit"                 refuse                         "--detach $F" 0.2.1 --release-commit $F
# the tree's version coordinates
t "release/0.5.x, 0.5.0, README names 0.3.0"             "refuse:README.md"             release/0.5.x 0.5.0
t "release/0.6.x, 0.6.0, iOS guide names 0.3.0"          "refuse:docs/guide/ios.md"     release/0.6.x 0.6.0
t "release/0.7.x, 0.7.0, BOM fallback 0.3.0-SNAPSHOT"    "refuse:kuicksilver-bom"       release/0.7.x 0.7.0
t "release/0.8.x, 0.8.0, BOM fallback missing"           "refuse:kuicksilver-bom"       release/0.8.x 0.8.0
t "release/0.9.x, 0.9.0, README 'in preparation'"        "refuse:in preparation"        release/0.9.x 0.9.0
t "release/0.10.x, 0.10.0, README 'Until ... on Central'" "refuse:Until 0.10.0 is on Maven Central" release/0.10.x 0.10.0
t "negative_installPageCoordinatesNotMoved"              "refuse:docs/install.md names 0.11.0 0.3.0 instead of 0.11.0" release/0.11.x 0.11.0
t "negative_installPageMissing"                          "refuse:docs/install.md names no version instead of 0.13.0" release/0.13.x 0.13.0
t "negative_installPageSwiftLineNotMoved"                "refuse:docs/install.md names 0.14.0 0.3.0 instead of 0.14.0" release/0.14.x 0.14.0
t "negative_installPageStillInPreparation"               "refuse:docs/install.md still calls 0.12.0 the release in preparation" release/0.12.x 0.12.0
# the Swift package (swift-package.sh prepare, before the gate): a tag of the version there means it is released already
KSL_SWIFT_REPO="$tmp/swift-tagged.git" t "Swift package already tagged 0.2.1" "refuse:tag 0.2.1 is already in" release/0.2.x 0.2.1
KSL_SWIFT_REPO="$tmp/no-such.git" t "Swift package repository unreachable" "refuse:Swift package cannot be prepared: cannot clone" release/0.2.x 0.2.1
KSL_SWIFT_REPO="$tmp/no-such.git" t "dry run: Swift package repository unreachable" "ok:WARN.*cannot clone" release/0.2.x 0.2.1 --dry-run
KSL_SWIFT_REPO="$tmp/swift-tagged.git" t "dry run: Swift package already tagged" "ok:WARN.*tag 0.2.1 is already in" release/0.2.x 0.2.1 --dry-run
t "Swift package prepared"                               "ok:prepared: .*no tag 0.2.1 yet" release/0.2.x 0.2.1
# the iOS guide's Swift package line names the version like its other coordinates
t "release/0.15.x, 0.15.0, iOS guide SwiftPM line 0.3.0" "refuse:docs/guide/ios.md names 0.15.0 0.3.0" release/0.15.x 0.15.0
# dry runs: refusals are warnings
t "dry run: release/0.2.x, 0.3.0"                        "ok:WARN.*maintenance branch"  release/0.2.x 0.3.0 --dry-run
t "dry run: feature, 0.2.1"                              ok:WARN                        feature 0.2.1 --dry-run
t "dry run: main, 0.2.1 while release/0.2.x exists"      "ok:WARN.*release/0.2.x exists" main 0.2.1 --dry-run
t "dry run: release/0.2.x, 0.2.2 without the bump"       "ok:WARN.*0.2.1-SNAPSHOT"      release/0.2.x 0.2.2 --dry-run
git push -q origin release/0.2.x
t "release/0.2.x after push: no note"                    ok                             release/0.2.x 0.2.1
t "--release-commit pushed branch tip: no note"          ok                             "--detach $B" 0.2.1 --release-commit $B
# a maintenance branch only on origin counts as well, fetched by the script in release mode
git push -q origin release/0.1.x:release/0.3.x; git update-ref -d refs/remotes/origin/release/0.3.x
t "main, 0.3.0, origin/release/0.3.x exists, not fetched" "refuse:release/0.3.x exists" main 0.3.0
git fetch -q origin
t "main, 0.3.0 while origin/release/0.3.x is fetched"        "refuse:release/0.3.x exists"  main 0.3.0
git push -q origin :release/0.3.x; git fetch -q --prune origin
t "main, 0.3.0 after origin/release/0.3.x is deleted"    ok:push_branch=main            main 0.3.0
# a local branch behind origin would release an older commit
git checkout -q -b ahead release/0.2.x; echo d > d; commit "pushed from elsewhere"; git push -q origin ahead:release/0.2.x
git checkout -q release/0.2.x; git branch -q -D ahead; git update-ref refs/remotes/origin/release/0.2.x "$B"   # not fetched yet
t "release/0.2.x behind origin (not fetched yet)"        "refuse:behind origin by 1 commit" release/0.2.x 0.2.1
t "--release-commit of the older tip: by design"         ok:push_branch=release/0.2.x   "--detach $B" 0.2.1 --release-commit $B
git fetch -q origin
t "dry run: behind origin, fetched (warning only)"      "ok:WARN.*behind origin by 1"  release/0.2.x 0.2.1 --dry-run
git push -q -f origin release/0.2.x; git fetch -q origin
t "release/0.2.x level with origin again"                ok:push_branch=release/0.2.x   release/0.2.x 0.2.1
# Maven Central (release mode only; a dry run may be offline)
t "0.2.0, already on Maven Central"                      "refuse:0.2.0 is already on Maven Central" release/0.2.x 0.2.0
t "dry run: 0.2.0, Central not asked"                    ok                             release/0.2.x 0.2.0 --dry-run
KSL_CENTRAL_STATUS=000 t "Central does not answer"        "refuse:could not ask Maven Central" release/0.2.x 0.2.1
KSL_CENTRAL_STATUS=503 t "Central answers 503"            "refuse:could not ask Maven Central" release/0.2.x 0.2.1
# CHANGELOG
t "CHANGELOG 0.2.9 - unreleased (placeholder)"           "refuse:no release date"       release/0.2.x 0.2.9
t "CHANGELOG [0.2.8] without date"                       "refuse:no release date"       release/0.2.x 0.2.8
t "CHANGELOG without 0.2.7"                              "refuse:has no '## \[0.2.7\]'" release/0.2.x 0.2.7
t "dry run: placeholder date (warning only)"             ok:WARN                        release/0.2.x 0.2.9 --dry-run
# --github-prerelease: a prerelease only, as a GitHub release; the Swift package is prepared as for a release
t "negative_githubPrereleaseFinalVersion"                "refuse:--github-prerelease takes a prerelease" release/0.2.x 0.2.1 --github-prerelease
t "negative_githubPrereleaseFinalVersionDryRun"          "refuse:--github-prerelease takes a prerelease" release/0.2.x 0.2.1 --github-prerelease --dry-run
t "--github-prerelease, 0.4.0-rc1"                       "ok:prepared: .*no tag 0.4.0-rc1 yet" release/0.4.x 0.4.0-rc1 --github-prerelease
KSL_SWIFT_REPO="$tmp/swift-tagged.git" t "negative_githubPrereleaseSwiftTagged" "refuse:tag 0.4.0-rc1 is already in" release/0.4.x 0.4.0-rc1 --github-prerelease
KSL_SWIFT_REPO="$tmp/no-such.git" t "negative_githubPrereleaseSwiftUnreachable" "refuse:Swift package cannot be prepared: cannot clone" release/0.4.x 0.4.0-rc1 --github-prerelease
git checkout -q main

# tools/release/swift-package.sh against a local package repository; the maintainer's signing, tagging and pushing are
# done here as a plain tag and push (ptag)
sp_pass() { pass=$((pass+1)); printf 'ok   %s\n' "$1"; }
sp_fail() { fail=$((fail+1)); printf 'FAIL %s: %s\n' "$1" "$2"; }
sp() { # <label> <ok|refuse> <pattern|-> <prepare|finish> <args...>: runs swift-package.sh (output in $sp_out, checkout in $tmp/sp)
  local label="$1" exp="$2" pat="$3" rc; shift 3
  sp_out=$(TZ=Asia/Tokyo KSL_SWIFT_REPO="${SP_REPO:-$tmp/sp.git}" bash "$root/tools/release/swift-package.sh" "$@" --out "$tmp/sp" 2>&1); rc=$?
  if [ "$([ $rc = 0 ] && echo ok || echo refuse)" != "$exp" ]; then sp_fail "$label" "exit $rc: $(tr '\n' ' ' <<< "$sp_out" | cut -c1-200)"
  elif [ "$pat" != - ] && ! grep -qE -- "$pat" <<< "$sp_out"; then sp_fail "$label" "no '$pat' in: $(tr '\n' ' ' <<< "$sp_out" | cut -c1-200)"
  else return 0; fi; return 1
}
ptag() { # <version> <branch>: what the maintainer does after finish (the test key, in UTC; the clone's hook checks it)
  TZ=UTC git -C "$tmp/sp" commit -q --amend --no-edit -S && TZ=UTC git -C "$tmp/sp" tag -s "$1" -m "Kuicksilver $1" && git -C "$tmp/sp" push -q --atomic "$tmp/sp.git" "$2" "refs/tags/$1" > "$tmp/ptag.log" 2>&1
}
git init -q --bare -b main "$tmp/sp.git"
S1=$(printf a | shasum -a 256 | cut -d' ' -f1); S2=$(printf b | shasum -a 256 | cut -d' ' -f1)
pkg_line() { sed -n "s/^ *$1: \"\(.*\)\",\{0,1\}$/\1/p" "$tmp/sp/Package.swift"; }
L="swift package: prepare leaves nothing committed"
if sp "$L" ok "prepared: .*branch main, no tag 0.3.0 yet" prepare 0.3.0; then
  if ! git -C "$tmp/sp" rev-parse -q --verify HEAD >/dev/null && [ -n "$(pkg_line checksum)" ]; then sp_pass "$L"; else sp_fail "$L" "a commit, or no rendered Package.swift"; fi
fi
L="swift package: first version into the empty repository"
if sp "$L" ok "commit [0-9a-f]+ on main, checksum $S1 \(unsigned, no tag yet\)" finish 0.3.0 "$S1" --source-commit 1234567; then
  if [ "$(pkg_line url)" = https://github.com/kuicksilver/kuicksilver/releases/download/v0.3.0/Kuicksilver.xcframework.zip ] && [ "$(pkg_line checksum)" = "$S1" ] \
      && ! git -C "$tmp/sp" rev-parse -q --verify refs/tags/0.3.0 >/dev/null && [ -f "$tmp/sp/LICENSE" ] && [ -f "$tmp/sp/licenses/LICENSE.openssl.txt" ] \
      && grep -q 'upToNextMinor(from: "0.3.0")' "$tmp/sp/README.md" && grep -q 'kuicksilver/kuicksilver@1234567' <<< "$(git -C "$tmp/sp" log -1 --format=%B)" \
      && [ "$(git -C "$tmp/sp" log -1 --format='%an <%ae> %G?')" = "Kuicksilver <hello@kuicksilver.io> N" ] \
      && grep -q 'git commit --amend --no-edit -S22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68' <<< "$sp_out" \
      && [ "$(git -C "$tmp/sp" log -1 --format='%ad %cd' --date=format:%z)" = "+0000 +0000" ] \
      && grep -qx '    export GPG_TTY=$(tty) TZ=UTC' <<< "$sp_out" \
      && grep -qx "    $(printf %q "$root")/tools/release/swift-package-check.sh prepush 0.3.0 --package $tmp/sp" <<< "$sp_out" \
      && grep -q 'git tag -s -u 22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68 0.3.0 -m "Kuicksilver 0.3.0"' <<< "$sp_out" \
      && grep -q "git push --atomic https://github.com/kuicksilver/kuicksilver-swift.git main refs/tags/0.3.0" <<< "$sp_out" \
      && grep -qx "    cd $tmp/sp" <<< "$sp_out" \
      && grep -qx "    $(printf %q "$root")/tools/release/swift-package.sh finish 0.3.0 $S1 --source-commit 1234567" <<< "$sp_out"
  then sp_pass "$L"; else sp_fail "$L" "files, tag, author, signing or push lines wrong"; fi
fi
ptag 0.3.0 main
L="swift package: next version on top of the published one"
if sp "$L" ok "on main" finish 0.3.1 "$S2"; then
  if [ "$(git -C "$tmp/sp" rev-list --count main)" = 2 ] && [ "$(pkg_line checksum)" = "$S2" ]; then sp_pass "$L"; else sp_fail "$L" "history or checksum wrong"; fi
fi
ptag 0.3.1 main
sp "swift package: version already tagged" refuse "tag 0.3.0 is already in" finish 0.3.0 "$S2" && sp_pass "swift package: version already tagged"
sp "swift package: prepare refuses a tagged version" refuse "tag 0.3.1 is already in" prepare 0.3.1 && sp_pass "swift package: prepare refuses a tagged version"
sp "dry run: version already tagged (warning)" ok "WARN.*tag 0.3.0 is already in" finish 0.3.0 "$S2" --dry-run && sp_pass "dry run: version already tagged (warning)"
sp "swift package: older line with nothing below it" refuse "0.2.0 is older than every version" finish 0.2.0 "$S1" \
  && sp_pass "swift package: older line with nothing below it"
# an older line after a newer one: main stays on 0.3.x, 0.2.3 goes on release/0.2.x (a new branch, then on top of it)
git -C "$tmp/sp" checkout -q --orphan old && git -C "$tmp/sp" -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m "0.2.2" \
  && git -C "$tmp/sp" tag 0.2.2 && git -C "$tmp/sp" push -q --no-verify "$tmp/sp.git" refs/tags/0.2.2
L="swift package: older line on release/0.2.x from its newest tag"
if sp "$L" ok "branch release/0.2.x \(an older line than 0.3: main stays on the newest\)" finish 0.2.3 "$S1"; then
  if [ "$(git -C "$tmp/sp" rev-parse HEAD~1)" = "$(git -C "$tmp/sp" rev-parse '0.2.2^{commit}')" ] && grep -q "push --atomic https://github.com/kuicksilver/kuicksilver-swift.git release/0.2.x refs/tags/0.2.3" <<< "$sp_out" \
      && [ "$(git -C "$tmp/sp.git" rev-parse main)" = "$(git -C "$tmp/sp.git" rev-parse '0.3.1^{commit}')" ]
  then sp_pass "$L"; else sp_fail "$L" "base, push line or main wrong"; fi
fi
ptag 0.2.3 release/0.2.x
L="swift package: older line again on top of release/0.2.x"
if sp "$L" ok "on release/0.2.x" finish 0.2.4 "$S2"; then
  [ "$(git -C "$tmp/sp" rev-parse HEAD~1)" = "$(git -C "$tmp/sp" rev-parse '0.2.3^{commit}')" ] && sp_pass "$L" || sp_fail "$L" "not on top of 0.2.3"
fi
sp "swift package: a newer line moves main" ok "on main" finish 1.0.0 "$S1" && sp_pass "swift package: a newer line moves main"
ptag 1.0.0 main
# the first package release of an older line without a tag of its own: from the newest final version below it, not main
L="swift package: first release of an older line from the version below it"
if sp "$L" ok "on release/0.5.x" finish 0.5.0 "$S2"; then
  [ "$(git -C "$tmp/sp" rev-parse HEAD~1)" = "$(git -C "$tmp/sp" rev-parse '0.3.1^{commit}')" ] && sp_pass "$L" || sp_fail "$L" "not based on 0.3.1"
fi
sp "swift package: all-zero checksum" refuse "not the SHA-256" finish 0.3.2 0000000000000000000000000000000000000000000000000000000000000000 && sp_pass "swift package: all-zero checksum"
sp "swift package: short checksum" refuse "not the SHA-256" finish 0.3.2 c9e7447 && sp_pass "swift package: short checksum"
sp "swift package: malformed version" refuse "is not X.Y.Z" finish v0.3.2 "$S1" && sp_pass "swift package: malformed version"
SP_REPO="$tmp/no-such.git" sp "swift package: repository unreachable" refuse "cannot clone" prepare 0.3.2 && sp_pass "swift package: repository unreachable"
L="dry run: repository unreachable (a new one)"
if SP_REPO="$tmp/no-such.git" sp "$L" ok "WARN.*cannot clone" finish 0.3.2 "$S1" --dry-run; then
  [ "$(git -C "$tmp/sp" rev-list --count main)" = 1 ] && sp_pass "$L" || sp_fail "$L" "not a fresh history"
fi
L="swift package: prerelease (exact:)"
if sp "$L" ok "on main" finish 1.1.0-rc1 "$S1"; then
  grep -q 'exact: "1.1.0-rc1"' <<< "$sp_out" && grep -q 'exact: "1.1.0-rc1"' "$tmp/sp/README.md" && ! grep -q upToNextMinor "$tmp/sp/README.md" \
    && [ "$(pkg_line url)" = https://github.com/kuicksilver/kuicksilver/releases/download/v1.1.0-rc1/Kuicksilver.xcframework.zip ] \
    && sp_pass "$L" || sp_fail "$L" "requirement or URL wrong"
fi

# the pre-push hook swift-package.sh installs in its clone (tools/release/swift-package-pre-push.sh): a push of a tag with
# a +0500 tagger date, of a commit naming a home directory, or of a +0500 commit is refused; the clean one goes through
git init -q --bare -b main "$tmp/sph.git"
SH=$(printf '%s' c | shasum -a 256 | cut -d' ' -f1)
KSL_SWIFT_REPO="$tmp/sph.git" bash "$root/tools/release/swift-package.sh" finish 2.0.0-rc1 "$SH" --out "$tmp/sph" >/dev/null 2>&1 \
  || { echo "FAIL: swift-package.sh finish for the hook cases"; exit 2; }
hpush() { # <label> <ok|refuse> <pattern|->: pushes main and the tag 2.0.0-rc1 of $tmp/sph to $tmp/sph.git
  local out rc; out=$(git -C "$tmp/sph" push --atomic "$tmp/sph.git" main refs/tags/2.0.0-rc1 2>&1); rc=$?
  if [ "$([ $rc = 0 ] && echo ok || echo refuse)" = "$2" ] && { [ "$3" = - ] || grep -qE -- "$3" <<< "$out"; } \
      && { [ "$2" = ok ] || ! git -C "$tmp/sph.git" rev-parse -q --verify refs/tags/2.0.0-rc1 >/dev/null; }; then sp_pass "$1"
  else sp_fail "$1" "exit $rc: $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
}
htag() { git -C "$tmp/sph" tag -d 2.0.0-rc1 >/dev/null 2>&1; TZ="$1" git -C "$tmp/sph" tag -s 2.0.0-rc1 -m "Kuicksilver 2.0.0-rc1"; }
[ "$(git -C "$tmp/sph" config core.hooksPath)" = "$(cd "$tmp/sph" && pwd)/.git/hooks" ] && [ -x "$tmp/sph/.git/hooks/pre-push" ] \
  && sp_pass "swift package: the clone has its pre-push hook" || sp_fail "swift package: the clone has its pre-push hook" "no hook"
htag Asia/Yekaterinburg; hpush "negative_swiftPushTaggerZone"     refuse "tagger zone [+]0500"
htag UTC; printf 'built in /Users/someone/src\n' > "$tmp/sph/NOTES"; git -C "$tmp/sph" add NOTES
TZ=UTC git -C "$tmp/sph" commit -q --no-gpg-sign -m notes; htag UTC
hpush "negative_swiftPushHomePath"        refuse "names a home directory"
git -C "$tmp/sph" reset -q --hard HEAD~1; TZ=Asia/Yekaterinburg git -C "$tmp/sph" commit -q --amend --no-edit --no-gpg-sign --reset-author; htag UTC
hpush "negative_swiftPushCommitZone"      refuse "[+]0500"
TZ=UTC git -C "$tmp/sph" commit -q --amend --no-edit -S --reset-author; htag UTC
out=$(git -C "$tmp/sph" push "$tmp/sph.git" HEAD:refs/tags/2.0.0-rc1 2>&1)
if [ $? != 0 ] && grep -q "must be the annotated tag 2.0.0-rc1 itself" <<< "$out" && ! git -C "$tmp/sph.git" rev-parse -q --verify refs/tags/2.0.0-rc1 >/dev/null
then sp_pass "negative_swiftPushCommitAsTag"; else sp_fail "negative_swiftPushCommitAsTag" "$(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
out=$(cd "$tmp/sph" && printf 'refs/heads/main %s refs/heads/main %s\n' "$(git rev-parse HEAD)" 0000000000000000000000000000000000000000 \
  | bash "$root/tools/release/swift-package-pre-push.sh" nowhere "$tmp/no-such-remote.git" 2>&1)
if [ $? != 0 ] && grep -q "cannot list $tmp/no-such-remote.git" <<< "$out"; then sp_pass "negative_swiftPushUnlistableRemote"
else sp_fail "negative_swiftPushUnlistableRemote" "$(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
hpush "swift package: a clean push goes through the hook" ok -
TZ=UTC git -C "$tmp/sph" commit -q --allow-empty --no-gpg-sign -m "unsigned"
out=$(git -C "$tmp/sph" push "$tmp/sph.git" main 2>&1)
if [ $? != 0 ] && grep -q "is not signed (git commit -S)" <<< "$out" && [ "$(git -C "$tmp/sph.git" rev-parse main)" != "$(git -C "$tmp/sph" rev-parse HEAD)" ]
then sp_pass "negative_swiftPushUnsignedCommit"; else sp_fail "negative_swiftPushUnsignedCommit" "$(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
git init -q --bare -b main "$tmp/spr.git"
KSL_SWIFT_AUTHOR="Rel Ease <rel@example.invalid>" KSL_SWIFT_REPO="$tmp/spr.git" bash "$root/tools/release/swift-package.sh" finish 3.0.0-rc1 "$SH" --out "$tmp/spr" >/dev/null 2>&1 \
  || { echo "FAIL: swift-package.sh finish with another identity"; exit 2; }
TZ=UTC git -C "$tmp/spr" commit -q --amend --no-edit -S; TZ=UTC git -C "$tmp/spr" tag -s 3.0.0-rc1 -m "Kuicksilver 3.0.0-rc1"
out=$(env -u KSL_SWIFT_AUTHOR git -C "$tmp/spr" push --atomic "$tmp/spr.git" main refs/tags/3.0.0-rc1 2>&1)
if [ $? = 0 ] && [ "$(git -C "$tmp/spr" config kuicksilver.swift.author)" = "Rel Ease <rel@example.invalid>" ]; then sp_pass "swift package: the hook reads the identity the clone stores"
else sp_fail "swift package: the hook reads the identity the clone stores" "$(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
out=$(git -C "$tmp/sph" push "$tmp/sph.git" :refs/tags/2.0.0-rc1 2>&1)
if [ $? != 0 ] && grep -q "deleting refs/tags/2.0.0-rc1 is refused" <<< "$out" && git -C "$tmp/sph.git" rev-parse -q --verify refs/tags/2.0.0-rc1 >/dev/null
then sp_pass "negative_swiftPushDeleteTag"; else sp_fail "negative_swiftPushDeleteTag" "$(tr '\n' ' ' <<< "$out")"; fi

# tools/release/swift-package-check.sh on the 1.1.0-rc1 commit just made (checksum S1, the SHA-256 of "a"); the GitHub
# release is a stub download (KSL_SWIFT_FETCH copies $KSL_TEST_REMOTE). Its iOS builds need a real xcframework: not here
printf 'a' > "$tmp/zip-a"; printf 'b' > "$tmp/zip-b"
printf '#!/bin/sh\n[ -f "$KSL_TEST_REMOTE" ] || exit 22\ncp "$KSL_TEST_REMOTE" "$2"\n' > "$tmp/bin/fetch"; chmod +x "$tmp/bin/fetch"
# gh for --draft: release download copies $KSL_TEST_REMOTE into -D <dir>, release view prints $KSL_TEST_DIGEST
printf '%s\n' '#!/bin/sh' 'case "$1 $2" in' \
  '  "release download") [ -f "$KSL_TEST_REMOTE" ] || exit 1; while [ $# -gt 0 ]; do [ "$1" = -D ] && d="$2"; shift; done' \
  '    mkdir -p "$d" && cp "$KSL_TEST_REMOTE" "$d/Kuicksilver.xcframework.zip" ;;' \
  '  "release view") printf "%s\n" "${KSL_TEST_DIGEST:-}" ;;' '  *) exit 2 ;;' 'esac' > "$tmp/bin/gh"; chmod +x "$tmp/bin/gh"
spc() { # <label> <ok|refuse> <pattern> <remote file> <args...>
  local label="$1" exp="$2" pat="$3" rc out; export KSL_TEST_REMOTE="$4"; shift 4
  out=$(KSL_GH="$tmp/bin/gh" KSL_SWIFT_FETCH="$tmp/bin/fetch" bash "$root/tools/release/swift-package-check.sh" "$@" --package "$tmp/sp" 2>&1); rc=$?
  if [ "$([ $rc = 0 ] && echo ok || echo refuse)" = "$exp" ] && grep -qE -- "$pat" <<< "$out"; then sp_pass "$label"
  else sp_fail "$label" "exit $rc: $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
}
spc "swift check: remote zip matches Package.swift and the local zip" ok "may be made and pushed" "$tmp/zip-a" remote 1.1.0-rc1 --zip "$tmp/zip-a"
spc "negative_swiftCheckRemoteChecksum"         refuse "do not push the tag"               "$tmp/zip-b" remote 1.1.0-rc1 --zip "$tmp/zip-a"
spc "negative_swiftCheckRemoteNotTheLocalZip"   refuse "differs from"                      "$tmp/zip-a" remote 1.1.0-rc1 --zip "$tmp/zip-b"
spc "negative_swiftCheckRemoteUnreachable"      refuse "cannot download"                   "$tmp/none"  remote 1.1.0-rc1 --zip "$tmp/zip-a"
spc "negative_swiftCheckOtherVersion"           refuse "not https://.*/v1.1.0-rc2/"        "$tmp/zip-a" remote 1.1.0-rc2
spc "negative_swiftCheckLocalChecksum"          refuse "Package.swift names $S1"           "$tmp/zip-a" local 1.1.0-rc1 --zip "$tmp/zip-b"
spc "negative_swiftCheckLocalNoZip"             refuse "is missing"                        "$tmp/zip-a" local 1.1.0-rc1 --zip "$tmp/none"
KSL_TEST_DIGEST="sha256:$S1" spc "swift check: draft asset and GitHub's digest" ok "remote check of the draft passed" "$tmp/zip-a" remote 1.1.0-rc1 --draft --zip "$tmp/zip-a"
spc "swift check: draft asset, no digest reported" ok "reports no digest"         "$tmp/zip-a" remote 1.1.0-rc1 --draft --zip "$tmp/zip-a"
KSL_TEST_DIGEST="sha256:$S2" spc "negative_swiftCheckDraftDigest" refuse "GitHub's digest of the asset is sha256:$S2" "$tmp/zip-a" remote 1.1.0-rc1 --draft
spc "negative_swiftCheckDraftChecksum"          refuse "do not push the tag"               "$tmp/zip-b" remote 1.1.0-rc1 --draft
spc "negative_swiftCheckDraftMissing"           refuse "gh cannot download"                "$tmp/none"  remote 1.1.0-rc1 --draft
# the commit and its tag: UTC dates (the Swift package repository is public, its tags immutable), no home path
spc "swift check: files of the commit"          ok     "no file, commit message or tag"    "$tmp/zip-a" files 1.1.0-rc1
spc "negative_swiftCheckPrepushNoTag"           refuse "no annotated tag 1.1.0-rc1"        "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag 1.1.0-rc1
spc "negative_swiftCheckPrepushLightweightTag"  refuse "no annotated tag 1.1.0-rc1"        "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null; TZ=Asia/Tokyo git -C "$tmp/sp" tag -s 1.1.0-rc1 -m x
spc "negative_swiftCheckPrepushTaggerZone"      refuse "tagger zone [+]0900"                "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null; TZ=UTC git -C "$tmp/sp" commit -q --amend --no-edit -S; TZ=UTC git -C "$tmp/sp" tag -s 1.1.0-rc1 -m x
spc "swift check: prepush, UTC tag on HEAD"     ok     "prepush check .* passed"           "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null; TZ=UTC git -C "$tmp/sp" tag -a 1.1.0-rc1 -m x
spc "negative_swiftCheckUnsignedTag"            refuse "is not signed [(]git tag -s[)]"      "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null; TZ=UTC git -C "$tmp/sp" tag -s -u "$OTHER_FPR" 1.1.0-rc1 -m x
spc "negative_swiftCheckTagOtherKey"            refuse "not signed by $FPR"                "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null; TZ=UTC git -C "$tmp/sp" -c user.name=Other -c user.email=o@example.invalid tag -s 1.1.0-rc1 -m x
spc "negative_swiftCheckTaggerIdentity"         refuse "tagger 'Other <o@example.invalid>'" "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null
# the commands the maintainer runs (amend, tag) take the clone's identity, not the global one (Global Person here)
TZ=UTC git -C "$tmp/sp" commit -q --amend --no-edit -S; TZ=UTC git -C "$tmp/sp" tag -s 1.1.0-rc1 -m x
spc "swift check: amend and tag ignore the global identity" ok "tagger Kuicksilver"           "$tmp/zip-a" prepush 1.1.0-rc1
# the commit's own signature (gpgsig), checked against the pinned key like the tag's
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null; TZ=UTC git -C "$tmp/sp" commit -q --amend --no-edit --no-gpg-sign; TZ=UTC git -C "$tmp/sp" tag -s 1.1.0-rc1 -m x
spc "negative_swiftCheckUnsignedCommit"         refuse "the commit [0-9a-f]+ is not signed [(]git commit -S[)]" "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null; TZ=UTC git -C "$tmp/sp" commit -q --amend --no-edit -S"$OTHER_FPR"; TZ=UTC git -C "$tmp/sp" tag -s 1.1.0-rc1 -m x
spc "negative_swiftCheckCommitOtherKey"         refuse "the commit [0-9a-f]+ is not signed by $FPR" "$tmp/zip-a" prepush 1.1.0-rc1
# the signature is read from the commit header only: a message line that starts with "gpgsig " is message
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null
TZ=UTC git -C "$tmp/sp" commit -q --amend -S -m "Kuicksilver 1.1.0-rc1" -m "gpgsig in the message, not a header"
TZ=UTC git -C "$tmp/sp" tag -s 1.1.0-rc1 -m x
spc "swift check: a 'gpgsig ' line in the message"  ok "the commit [0-9a-f]+ is signed by $FPR" "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null
TZ=UTC git -C "$tmp/sp" -c user.name=Other -c user.email=o@example.invalid commit -q --amend --no-edit --no-gpg-sign
spc "negative_swiftCheckCommitterIdentity"      refuse "author[|]committer is"              "$tmp/zip-a" files 1.1.0-rc1
TZ=UTC git -C "$tmp/sp" -c user.name=kinchpik -c user.email=339333647+kinchpik@users.noreply.github.com commit -q --amend --no-edit --no-gpg-sign --reset-author
spc "negative_swiftCheckCommitByCommitIdentity" refuse "author[|]committer is 'kinchpik"     "$tmp/zip-a" files 1.1.0-rc1
TZ=UTC git -C "$tmp/sp" commit -q --amend --no-edit --no-gpg-sign --reset-author
TZ=Asia/Tokyo git -C "$tmp/sp" commit -q --amend --no-edit --no-gpg-sign --reset-author
spc "negative_swiftCheckCommitZone"             refuse "zones [+]0900 [+]0900"               "$tmp/zip-a" files 1.1.0-rc1
spc "negative_swiftCheckLocalCommitZone"        refuse "zones [+]0900"                      "$tmp/zip-a" local 1.1.0-rc1 --zip "$tmp/zip-a"
printf 'built in /Users/someone/src\n' > "$tmp/sp/NOTES"; git -C "$tmp/sp" add NOTES
TZ=UTC git -C "$tmp/sp" commit -q --amend --no-edit --no-gpg-sign --reset-author
spc "negative_swiftCheckHomePath"               refuse "names a home directory"            "$tmp/zip-a" files 1.1.0-rc1
git -C "$tmp/sp" rm -q NOTES
TZ=UTC git -C "$tmp/sp" commit -q --amend --no-gpg-sign --reset-author -m 'from C:\Users\someone\src'
spc "negative_swiftCheckHomePathInMessage"      refuse "names a home directory"            "$tmp/zip-a" files 1.1.0-rc1
TZ=UTC git -C "$tmp/sp" commit -q --amend --no-gpg-sign --reset-author -m 'Kuicksilver 1.1.0-rc1'
TZ=UTC git -C "$tmp/sp" tag -s 1.1.0-rc1 -m 'tagged in /home/someone/sp'
spc "negative_swiftCheckHomePathInTag"          refuse "names a home directory"            "$tmp/zip-a" prepush 1.1.0-rc1
git -C "$tmp/sp" tag -d 1.1.0-rc1 >/dev/null

# the local-gate check itself (local-release.sh from the marker line to the toolchain check) on fixture records: only a
# full run's passing stamp is a gate; a run of some steps (local-matrix.sh --only/--from) never is, whatever its file says
gate_block=$(awk -v m="$marker" '$0 ~ m {on = 1} /^# toolchains pinned/ {on = 0} on' "$root/tools/release/local-release.sh")
grep -q 'refuse' <<< "$gate_block" || { echo "FAIL: no local-gate check found after the marker line"; exit 2; }
gate_t() { # <label> <ok|refuse>[:<pattern>] <stamp lines...>: the check against build/ci/gate/<head>.stamp holding those lines
  local label="$1" exp="${2%%:*}" pat="" d out got verdict; [ "$2" = "${2#*:}" ] || pat="${2#*:}"; shift 2
  d="$tmp/gate-$pass-$fail"; mkdir -p "$d/build/ci/gate"; printf '%s\n' "$@" > "$d/build/ci/gate/c0ffee.stamp"
  out=$(cd "$d" && head=c0ffee short=c0ffee bash -c 'refuse() { echo "REFUSED: $*"; }; '"$gate_block" 2>&1)
  got=$(grep -q REFUSED <<< "$out" && echo refuse || echo ok)
  verdict=FAIL; if [ "$got" = "$exp" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<< "$out"; }; then verdict=ok; fi
  [ $verdict = ok ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-4s %-58s exp=%-6s got=%-6s | %s\n' "$verdict" "$label" "$exp" "$got" "$(grep REFUSED <<< "$out" | tr '\n' ' ' | cut -c1-230)"
}
full=(commit=c0ffee tree=clean skip_android=0 skip_docker=0 with_interop=1 with_windows=1 steps=72 failed=0)
gate_t "gate: a full run's passing stamp"                     ok                               result=pass selection=all "${full[@]}"
gate_t "negative_gateFailedStamp"                             "refuse:did not pass"            result=fail selection=all "${full[@]}"
gate_t "negative_gatePartialRecordAsStamp"                    "refuse:did not pass"            result=partial-pass selection=only=25 "${full[@]}"
gate_t "negative_gatePassWithSelection"                       "refuse:only some steps"         result=pass selection=from=3 "${full[@]}"
gate_t "negative_gateNoSelectionLine"                         "refuse:only some steps"         result=pass "${full[@]}"
gate_t "negative_gateWithoutWindows"                          "refuse:without --with-windows"  result=pass selection=all "${full[@]/with_windows=1/with_windows=0}"

# the credential check (local-release.sh from "# credentials and signing" to sign_args) against a fixture
# gradle.properties: --github-prerelease needs the signing key as a release does, never reads the Central Portal token,
# and leaves no ORG_GRADLE_PROJECT_mavenCentral* variable for Gradle
cred_block=$(awk '/^# credentials and signing/ {on = 1} /^sign_args=/ {on = 0} on' "$root/tools/release/local-release.sh")
grep -q 'mavenCentralUsername' <<< "$cred_block" || { echo "FAIL: no credential check found in local-release.sh"; exit 2; }
cred_t() { # <label> <ok|refuse>[:<pattern>] <gh 0|1> <gradle.properties lines...>
  local label="$1" exp="${2%%:*}" pat="" gh="$3" d out got verdict; [ "$2" = "${2#*:}" ] || pat="${2#*:}"; shift 3
  d="$tmp/cred-$pass-$fail"; mkdir -p "$d"; printf '%s\n' "$@" > "$d/gradle.properties"; : > "$d/key.gpg"
  out=$(cd "$d" && GRADLE_USER_HOME="$d" ORG_GRADLE_PROJECT_mavenCentralPassword="${CRED_ENV:-}" dry=0 unsigned=0 gh="$gh" \
    bash -c 'refuse() { echo "REFUSED: $*"; }; '"$cred_block"'
      echo "env-left=${ORG_GRADLE_PROJECT_mavenCentralPassword:-}${ORG_GRADLE_PROJECT_mavenCentralUsername:-}"' 2>&1)
  got=$(grep -q REFUSED <<< "$out" && echo refuse || echo ok)
  verdict=FAIL; if [ "$got" = "$exp" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<< "$out"; }; then verdict=ok; fi
  [ $verdict = ok ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-4s %-58s exp=%-6s got=%-6s | %s\n' "$verdict" "$label" "$exp" "$got" "$(grep -E 'REFUSED|Central|env-left' <<< "$out" | tr '\n' ' ' | cut -c1-230)"
}
key=(signing.keyId=0xC8D0EC68 signing.password=x "signing.secretKeyRingFile=key.gpg")
cred_t "credentials: a release without the Central token"     "refuse:no mavenCentralUsername"    0 "${key[@]}"
cred_t "credentials: --github-prerelease, no Central token"   "ok:Central Portal token: not read" 1 "${key[@]}"
cred_t "negative_githubPrereleaseWithoutSigningKey"           "refuse:no signing key"             1 mavenCentralUsername=u mavenCentralPassword=p
CRED_ENV=secret cred_t "credentials: --github-prerelease drops the token variables" "ok:env-left=$" 1 "${key[@]}"

# tools/release/github-repository.py: the Maven repository zip of a GitHub prerelease from a fixture publication
gr="$root/tools/release/github-repository.py"; V=0.4.0-rc1
mk_m2() { # <dir> [signed]: two modules (a BOM and a library), each file with its .asc when signed, Gradle's local metadata
  local m="$1/io/kuicksilver" a f
  for a in kuicksilver-bom kuicksilver-quic-jvm; do
    mkdir -p "$m/$a/$V"; printf '<metadata/>\n' > "$m/$a/maven-metadata-local.xml"
    printf '<project><artifactId>%s</artifactId><version>%s</version></project>\n' "$a" "$V" > "$m/$a/$V/$a-$V.pom"
    printf '{"formatVersion":"1.1"}\n' > "$m/$a/$V/$a-$V.module"
  done
  printf 'PK-jar\n' > "$m/kuicksilver-quic-jvm/$V/kuicksilver-quic-jvm-$V.jar"
  mkdir -p "$m/kuicksilver-quic-jvm/0.3.0"; printf 'old\n' > "$m/kuicksilver-quic-jvm/0.3.0/kuicksilver-quic-jvm-0.3.0.jar"
  if [ "${2:-}" = signed ]; then for f in $(find "$m" -path "*/$V/*" -type f); do printf 'sig\n' > "$f.asc"; done; fi
}
gr_t() { # <label> <ok|refuse>[:<pattern>] <fixture: signed|unsigned|nopom|nomodule|noasc|empty> <args...>
  local label="$1" exp="${2%%:*}" pat="" fx="$3" d out rc got verdict; [ "$2" = "${2#*:}" ] || pat="${2#*:}"; shift 3
  d="$tmp/gr-$pass-$fail"; mkdir -p "$d/m2" "$d/out"
  case "$fx" in
    signed|noasc) mk_m2 "$d/m2" signed ;; unsigned|nopom|nomodule) mk_m2 "$d/m2" ;; empty) ;;
  esac
  case "$fx" in
    nopom) rm "$d/m2/io/kuicksilver/kuicksilver-quic-jvm/$V/kuicksilver-quic-jvm-$V.pom" ;;
    nomodule) rm "$d/m2/io/kuicksilver/kuicksilver-quic-jvm/$V/kuicksilver-quic-jvm-$V.module" ;;
    noasc) rm "$d/m2/io/kuicksilver/kuicksilver-quic-jvm/$V/kuicksilver-quic-jvm-$V.jar.asc" ;;
  esac
  out=$(python3 -I "$gr" pack --m2 "$d/m2" --out-dir "$d/out" --time 1794688855 "$@" 2>&1); rc=$?
  got=$([ $rc = 0 ] && echo ok || echo refuse)
  verdict=FAIL; if [ "$got" = "$exp" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<< "$out"; }; then verdict=ok; fi
  [ $verdict = ok ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-4s %-58s exp=%-6s got=%-6s | %s\n' "$verdict" "$label" "$exp" "$got" "$(tr '\n' ' ' <<< "$out" | cut -c1-200)"
  gr_dir="$d/out"
}
gr_t "github repository: signed publication"                ok              signed   --version "$V" --signed
zip="$gr_dir/kuicksilver-$V-maven-repository.zip"; doc="$gr_dir/kuicksilver-$V-maven-repository.md"
L="github repository: zip layout, checksums, metadata"
entries=$(unzip -Z1 "$zip" 2>/dev/null | sort)
p="kuicksilver-$V-maven-repository/io/kuicksilver/kuicksilver-quic-jvm"
jar_sha1=$(printf 'PK-jar\n' | shasum -a 1 | cut -d' ' -f1)
if grep -qx "$p/$V/kuicksilver-quic-jvm-$V.jar" <<< "$entries" && grep -qx "$p/$V/kuicksilver-quic-jvm-$V.jar.asc" <<< "$entries" \
    && grep -qx "$p/$V/kuicksilver-quic-jvm-$V.pom.sha256" <<< "$entries" && grep -qx "$p/$V/kuicksilver-quic-jvm-$V.module.sha512" <<< "$entries" \
    && grep -qx "$p/$V/kuicksilver-quic-jvm-$V.jar.md5" <<< "$entries" \
    && [ "$(unzip -p "$zip" "$p/$V/kuicksilver-quic-jvm-$V.jar.sha1")" = "$jar_sha1" ] \
    && ! grep -q '\.asc\.' <<< "$entries" && ! grep -q 'maven-metadata-local' <<< "$entries" && ! grep -q '/0\.3\.0/' <<< "$entries" \
    && unzip -p "$zip" "$p/maven-metadata.xml" | grep -q "<version>$V</version>" && grep -qx "$p/maven-metadata.xml.sha1" <<< "$entries" \
    && grep -qx "kuicksilver-$V-maven-repository/README.md" <<< "$entries"; then
  pass=$((pass+1)); echo "ok   $L"; else fail=$((fail+1)); echo "FAIL $L: $(head -c 600 <<< "$entries" | tr '\n' ' ')"; fi
L="github repository: consumer instructions"
if [ -f "$doc" ] && grep -q "includeGroup(\"io.kuicksilver\")" "$doc" && grep -q 'uri("file:' "$doc" \
    && grep -q "platform(\"io.kuicksilver:kuicksilver-bom:$V\")" "$doc" && grep -q "releases/download/v$V/kuicksilver-$V-maven-repository.zip" "$doc" \
    && grep -q "not on Maven Central" "$doc" && grep -qF "kuicksilver-swift\", exact: \"$V\")" "$doc" && cmp -s "$doc" <(unzip -p "$zip" "kuicksilver-$V-maven-repository/README.md") \
    && ! grep -qE '/Users/|/home/' "$doc"; then
  pass=$((pass+1)); echo "ok   $L"; else fail=$((fail+1)); echo "FAIL $L"; fi
L="github repository: instructions that work (download, signatures and the provenance, Kotlin Multiplatform)"
# every asset SHA256SUMS lists must come with the documented download, or `shasum -c` fails on the missing ones
cover=$(python3 -I - "$doc" "$V" <<'PY'
import fnmatch, re, shlex, sys
doc, v = open(sys.argv[1]).read(), sys.argv[2]
line = next((l for l in doc.splitlines() if l.startswith("gh release download")), None)
if line is None: sys.exit("no gh release download line")
a = shlex.split(line); pats = [a[i + 1] for i, x in enumerate(a) if x in ("-p", "--pattern")]
names = [f"kuicksilver-{v}-maven-repository.zip", f"kuicksilver-{v}-maven-repository.md", f"kuicksilver-{v}-sbom.zip",
         f"kuicksilver-{v}.intoto.jsonl", "Kuicksilver.xcframework.zip", f"kuicksilver-{v}-SHA256SUMS"]
names += [n + ".asc" for n in names]
miss = [n for n in names if pats and not any(fnmatch.fnmatchcase(n, q) for q in pats)]
print("missing: " + " ".join(miss) if miss else "ok")
PY
)
if [ "$cover" = ok ] && grep -qF "implementation(project.dependencies.platform(\"io.kuicksilver:kuicksilver-bom:$V\"))" "$doc" \
    && grep -q 'sourceSets.commonMain.dependencies' "$doc" && grep -q '^gpg --import kuicksilver-release-key.asc' "$doc" \
    && grep -qxF "gpg --verify kuicksilver-$V.intoto.jsonl.asc kuicksilver-$V.intoto.jsonl" "$doc" \
    && grep -q 'every artifact,$' "$doc"; then
  pass=$((pass+1)); echo "ok   $L"; else fail=$((fail+1)); echo "FAIL $L: $cover"; fi
L="github repository: the same input gives the same zip"
mkdir -p "$gr_dir/again"; touch "$(dirname "$gr_dir")/m2/io/kuicksilver/kuicksilver-bom/$V/kuicksilver-bom-$V.pom"   # a newer mtime
if python3 -I "$gr" pack --m2 "$(dirname "$gr_dir")/m2" --out-dir "$gr_dir/again" --time 1794688855 --version "$V" --signed >/dev/null 2>&1 \
    && cmp -s "$zip" "$gr_dir/again/kuicksilver-$V-maven-repository.zip"; then pass=$((pass+1)); echo "ok   $L"; else fail=$((fail+1)); echo "FAIL $L"; fi
gr_t "github repository: unsigned dry run"                   ok              unsigned --version "$V"
gr_t "negative_githubRepositoryFinalVersion"                 "refuse:not a prerelease" signed --version 0.4.0 --signed
gr_t "negative_githubRepositoryMissingSignature"             "refuse:kuicksilver-quic-jvm-$V.jar.asc" noasc --version "$V" --signed
gr_t "negative_githubRepositoryMissingPom"                   "refuse:no POM"            nopom    --version "$V"
gr_t "negative_githubRepositoryMissingModule"                "refuse:no Gradle module"  nomodule --version "$V"
gr_t "negative_githubRepositoryEmpty"                        "refuse:no io.kuicksilver" empty    --version "$V"
gr_t "negative_githubRepositorySignedFlagUnsignedFiles"      "refuse:\.asc"             unsigned --version "$V" --signed
L="github repository: SHA256SUMS of the assets"
printf 'a\n' > "$gr_dir/a.bin"; printf 'b\n' > "$gr_dir/b.bin"
if python3 -I "$gr" sums --out "$gr_dir/SUMS" "$gr_dir/a.bin" "$gr_dir/b.bin" >/dev/null 2>&1 \
    && (cd "$gr_dir" && shasum -a 256 -c SUMS >/dev/null 2>&1) && [ "$(wc -l < "$gr_dir/SUMS" | tr -d ' ')" = 2 ] \
    && ! grep -q '/' "$gr_dir/SUMS"; then pass=$((pass+1)); echo "ok   $L"; else fail=$((fail+1)); echo "FAIL $L"; fi
L="negative_githubRepositorySumsMissingFile"
out=$(python3 -I "$gr" sums --out "$gr_dir/SUMS2" "$gr_dir/a.bin" "$gr_dir/missing.bin" 2>&1)
if [ $? != 0 ] && grep -q 'missing.bin: no such asset' <<< "$out" && [ ! -e "$gr_dir/SUMS2" ]; then
  pass=$((pass+1)); echo "ok   $L"; else fail=$((fail+1)); echo "FAIL $L"; fi

# tools/hooks/pre-push, the privacy guard of this repository, on pushes from a throwaway repository to a bare one: names
# come from git config kuicksilver.privacy.names (none are in the repository), the identity from kuicksilver.privacy.identity
hk="$tmp/hook"; mkdir -p "$hk/hooks"; ln -s "$root/tools/hooks/pre-push" "$hk/hooks/pre-push"
git init -q --bare -b main "$hk/remote.git"; git init -q -b main "$hk/w"
hg() { git -C "$hk/w" -c core.hooksPath="$hk/hooks" "$@"; }
hg config kuicksilver.privacy.names "zorbex quill"; hg config --add kuicksilver.privacy.names "qzx-alias"
hg config kuicksilver.privacy.identity "kinchpik <339333647+kinchpik@users.noreply.github.com>"
hg config kuicksilver.privacy.tagger "Kuicksilver <hello@kuicksilver.io>"
hcommit() { # <TZ> <message> [file content]: a commit by the configured identity
  [ -z "${3:-}" ] || printf '%s\n' "$3" > "$hk/w/f.txt"; hg add -A >/dev/null 2>&1
  TZ="$1" GIT_AUTHOR_NAME=kinchpik GIT_AUTHOR_EMAIL=339333647+kinchpik@users.noreply.github.com GIT_COMMITTER_NAME=kinchpik \
    GIT_COMMITTER_EMAIL=339333647+kinchpik@users.noreply.github.com hg commit -q --allow-empty --no-gpg-sign -m "$2"
}
mhook() { # <label> <ok|refuse> <pattern|-> <push args...>
  local label="$1" exp="$2" pat="$3" out rc; shift 3
  out=$(hg push "$hk/remote.git" "$@" 2>&1); rc=$?
  if [ "$([ $rc = 0 ] && echo ok || echo refuse)" = "$exp" ] && { [ "$pat" = - ] || grep -qE -- "$pat" <<< "$out"; }; then pass=$((pass+1)); echo "ok   $label"
  else fail=$((fail+1)); echo "FAIL $label: exit $rc: $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
}
hcommit UTC "base" "hello"; mhook "privacy hook: a clean UTC commit" ok - main
hcommit Asia/Yekaterinburg "zoned"; mhook "negative_hookCommitZone" refuse "non-UTC dates" main
hg reset -q --hard HEAD~1; hcommit UTC "by Zorbex.Quill"; mhook "negative_hookNameInMessage" refuse "personal identifiers in commit messages" main
hg reset -q --hard HEAD~1; hcommit UTC "data" "contact QZX-ALIAS"; mhook "negative_hookNameAdded" refuse "personal identifiers added" main
hg reset -q --hard HEAD~1; hcommit UTC "path" "see /Users/${USER:-$(id -un)}/x"; mhook "negative_hookHomePathAdded" refuse "personal identifiers added" main
hg reset -q --hard HEAD~1; hcommit UTC "host" "built on $(hostname | cut -d. -f1)"; mhook "negative_hookHostNameAdded" refuse "personal identifiers added" main
hg reset -q --hard HEAD~1; hg -c user.name=someone -c user.email=s@example.invalid commit -q --allow-empty --no-gpg-sign -m other
mhook "negative_hookOtherIdentity" refuse "another author/committer identity" main
hg reset -q --hard HEAD~1; TZ=Asia/Yekaterinburg hg -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -a v9 -m v9
mhook "negative_hookTaggerZone" refuse "tagger zone [+]0500" refs/tags/v9
hg tag -d v9 >/dev/null; TZ=UTC hg -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -a v9 -m v9
mhook "negative_hookUnsignedReleaseTag" refuse "tag v9 is not signed" refs/tags/v9
hg tag -d v9 >/dev/null; TZ=UTC hg -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -s -u "$OTHER_FPR" v9 -m v9
mhook "negative_hookReleaseTagOtherKey" refuse "tag v9 is not signed by the release key $FPR" refs/tags/v9
hg tag -d v9 >/dev/null; hg tag v9
mhook "negative_hookLightweightReleaseTag" refuse "v9: every tag pushed here is a release tag" refs/tags/v9
# every tag pushed here is a release tag, whatever its name
TZ=UTC hg -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -a 1.0.4 -m 1.0.4; mhook "negative_hookUnsignedTagAnyName" refuse "tag 1.0.4 is not signed" refs/tags/1.0.4
hg tag 1.0.5; mhook "negative_hookLightweightTagAnyName" refuse "1.0.5: every tag pushed here is a release tag" refs/tags/1.0.5
TZ=UTC hg -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -a V1.0.6 -m V1.0.6; mhook "negative_hookUnsignedTagCapitalV" refuse "tag V1.0.6 is not signed" refs/tags/V1.0.6
hg tag -d 1.0.4 1.0.5 V1.0.6 >/dev/null
hg tag -d v9 >/dev/null; TZ=UTC hg -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -s v9 -m v9
mhook "privacy hook: a signed UTC tag by the release identity, over commits by the maintainer" ok - main refs/tags/v9
# the throwaway key counts only in a test run (KSL_HOOK_TEST=1): without the flag, the pinned release key decides
TZ=UTC hg -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -s v10 -m v10
KSL_HOOK_TEST= mhook "negative_hookKeyOverrideWithoutTestFlag" refuse "tag v10 is not signed by the release key 22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68" refs/tags/v10
hg tag -d v10 >/dev/null
hg tag -d v9 >/dev/null; TZ=UTC hg -c user.name=kinchpik -c user.email=339333647+kinchpik@users.noreply.github.com tag -a v9 -m v9
mhook "negative_hookTagByCommitIdentity" refuse "tagger 'kinchpik <339333647[+]kinchpik@users.noreply.github.com>'" refs/tags/v9
hg tag -d v9 >/dev/null
TZ=UTC hg -c user.name=Other -c user.email=o@example.invalid tag -a v9 -m v9
mhook "negative_hookTaggerIdentity" refuse "tagger 'Other <o@example.invalid>'" refs/tags/v9
hg tag -d v9 >/dev/null
# a name in the author or committer itself (here also another identity: both are reported)
TZ=UTC GIT_AUTHOR_NAME="Zorbex Quill" GIT_AUTHOR_EMAIL=zq@example.invalid hg commit -q --allow-empty --no-gpg-sign -m plain
mhook "negative_hookNameInAuthor" refuse "personal identifiers in author/committer" main
hg reset -q --hard HEAD~1
# a force push over a remote commit this checkout does not have: the whole new history is checked, not skipped
git clone -q "$hk/remote.git" "$hk/other" && hcommit UTC "seed"
( cd "$hk/other" && TZ=UTC git -c user.name=kinchpik -c user.email=339333647+kinchpik@users.noreply.github.com commit -q --allow-empty --no-gpg-sign -m elsewhere \
  && git push -q --no-verify origin main ) || { echo "FAIL: force-push fixture"; exit 2; }
hg reset -q --hard HEAD~1; hcommit Asia/Yekaterinburg "zoned, force-pushed"
mhook "negative_hookForcePushUnknownRemoteCommit" refuse "non-UTC dates" --force main
# what a remote already has is not checked again: an old non-UTC commit there, a new one on top (by URL, and named)
hg fetch -q "$hk/remote.git" main && hg reset -q --hard FETCH_HEAD
( cd "$hk/other" && git pull -q && TZ=Asia/Yekaterinburg git -c user.name=kinchpik -c user.email=339333647+kinchpik@users.noreply.github.com commit -q --allow-empty --no-gpg-sign -m "old, zoned" \
  && git push -q --no-verify origin main ) || { echo "FAIL: published-history fixture"; exit 2; }
hg fetch -q "$hk/remote.git" main && hg reset -q --hard FETCH_HEAD; hcommit UTC "new on top"
mhook "privacy hook: published history is not checked again (URL)" ok - main
hg remote add r "$hk/remote.git"; hg fetch -q r; hcommit UTC "newer on top"
out=$(hg push r main 2>&1) && { pass=$((pass+1)); echo "ok   privacy hook: published history is not checked again (named remote)"; } \
  || { fail=$((fail+1)); echo "FAIL privacy hook: named remote: $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; }
hg remote add r2 "$hk/remote.git"; hcommit UTC "newest on top"
out=$(hg push r2 main 2>&1) && { pass=$((pass+1)); echo "ok   privacy hook: a named remote without tracking refs is listed (no old history)"; } \
  || { fail=$((fail+1)); echo "FAIL privacy hook: named remote without tracking refs: $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; }
out=$(cd "$hk/w" && printf 'refs/heads/main %s refs/heads/main %s\n' "$(git rev-parse HEAD)" 0000000000000000000000000000000000000000 \
  | sh "$root/tools/hooks/pre-push" "$hk/no-such.git" "$hk/no-such.git" 2>&1)
if [ $? != 0 ] && grep -q "cannot list $hk/no-such.git" <<< "$out"; then pass=$((pass+1)); echo "ok   negative_hookUnlistableRemote"
else fail=$((fail+1)); echo "FAIL negative_hookUnlistableRemote: $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
hg config --unset kuicksilver.privacy.tagger; hcommit UTC "next"
mhook "negative_hookNoTaggerConfigured" refuse "kuicksilver.privacy.tagger" main
hg config kuicksilver.privacy.tagger "Kuicksilver <hello@kuicksilver.io>"; hg config --unset kuicksilver.privacy.identity
mhook "negative_hookNoIdentityConfigured" refuse "kuicksilver.privacy.identity" main
hg config kuicksilver.privacy.identity "kinchpik <339333647+kinchpik@users.noreply.github.com>"; hg config --unset-all kuicksilver.privacy.names
mhook "negative_hookNoNamesConfigured" refuse "kuicksilver.privacy.names" main

# the release script's check of that hook (local-release.sh from "# the privacy pre-push hook" to the credential check)
hook_block=$(awk '/^# the privacy pre-push hook/ {on = 1} /^# credentials and signing/ {on = 0} on' "$root/tools/release/local-release.sh")
grep -q 'refuse' <<< "$hook_block" || { echo "FAIL: no pre-push hook check found in local-release.sh"; exit 2; }
hook_t() { # <label> <ok|refuse>[:<pattern>] <setup: linked|copied|other|none> [names] [identity] [user name] [tagger]
  local label="$1" exp="${2%%:*}" pat="" d out got verdict; [ "$2" = "${2#*:}" ] || pat="${2#*:}"
  d="$tmp/hookchk-$pass-$fail"; git init -q -b main "$d"; mkdir -p "$d/tools/hooks"; cp "$root/tools/hooks/pre-push" "$d/tools/hooks/"
  case "$3" in
    linked) ln -s ../../tools/hooks/pre-push "$d/.git/hooks/pre-push" ;; copied) cp "$root/tools/hooks/pre-push" "$d/.git/hooks/" ;;
    other) printf '#!/bin/sh\nexit 0\n' > "$d/.git/hooks/pre-push"; chmod +x "$d/.git/hooks/pre-push" ;; none) ;;
  esac
  [ -z "${4:-}" ] || git -C "$d" config kuicksilver.privacy.names "$4"
  [ -z "${5:-}" ] || git -C "$d" config kuicksilver.privacy.identity "$5"
  git -C "$d" config user.name "${6:-kinchpik}"; git -C "$d" config user.email 339333647+kinchpik@users.noreply.github.com
  [ "${7-Kuicksilver <hello@kuicksilver.io>}" = "" ] || git -C "$d" config kuicksilver.privacy.tagger "${7-Kuicksilver <hello@kuicksilver.io>}"
  mkdir -p "$d/tools/release"; cp "$root/tools/release/kuicksilver-release-key.asc" "$d/tools/release/"
  out=$(cd "$d" && bash -c 'refuse() { echo "REFUSED: $*"; }; '"$hook_block" 2>&1)
  got=$(grep -q REFUSED <<< "$out" && echo refuse || echo ok)
  verdict=FAIL; if [ "$got" = "$exp" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<< "$out"; }; then verdict=ok; fi
  [ $verdict = ok ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-4s %-58s exp=%-6s got=%-6s | %s\n' "$verdict" "$label" "$exp" "$got" "$(tr '\n' ' ' <<< "$out" | cut -c1-200)"
}
hook_t "hook check: linked, names and identity"     ok      linked "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>"
hook_t "hook check: copied, names and identity"     ok      copied "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>"
hook_t "negative_releaseWithoutHook"                 "refuse:privacy pre-push hook is not installed" none "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>"
hook_t "negative_releaseWithOtherHook"               "refuse:privacy pre-push hook is not installed" other "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>"
hook_t "negative_releaseWithoutPrivacyNames"         "refuse:kuicksilver.privacy.names"             linked "" "kinchpik <339333647+kinchpik@users.noreply.github.com>"
hook_t "negative_releaseWithoutPrivacyIdentity"      "refuse:kuicksilver.privacy.identity"          linked "zorbex quill"
hook_t "negative_releaseUserIsNotTheIdentity"        "refuse:user.name/user.email of this checkout"  linked "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>" "Global Person"
hook_t "negative_releaseWithoutTagger"               "refuse:no kuicksilver.privacy.tagger"         linked "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>" kinchpik ""
hook_t "negative_releaseTaggerNotAKeyUid"            "refuse:is not a user ID of the release key"   linked "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>" kinchpik "kinchpik <339333647+kinchpik@users.noreply.github.com>"
hook_t "hook check: prints the tag identity"         "ok:tags by Kuicksilver <hello@kuicksilver.io>" linked "zorbex quill" "kinchpik <339333647+kinchpik@users.noreply.github.com>"

# the end of a --github-prerelease run (local-release.sh from its Maven repository step to its last line) on a fixture
# publication. Gradle is a stub that records its arguments (sbomZip writes an archive, signReleaseFiles a .asc per file)
# and so is the signature check: nothing is built or signed. The invariants of the mode, for every run:
#   I1 nothing reaches Central: no Gradle call runs publishToMavenCentral, every one gets -x publishToMavenCentral and the
#      Central token empty, and the run ends before the Central upload (a missing exit would reach it);
#   I2 every published asset is signed and listed in SHA256SUMS: the printed draft release attaches exactly the twelve
#      expected files (six assets and their .asc), each exists, and SHA256SUMS lists exactly the six and their .asc;
#   I3 nothing published has a non-UTC date or a local path: the Swift package commit is +0000 and a commit or file
#      that is not makes the run fail, as does a home path in the publication; a final version never gets this far.
# Each attack below tries to break one of them; an attack must fail the run before the release commands are printed.
tail_block=$(awk '/^# --github-prerelease: the publication as a Maven repository zip/ {on = 1} on' "$root/tools/release/local-release.sh")
grep -q 'gh release create' <<< "$tail_block" || { echo "FAIL: no GitHub prerelease block found in local-release.sh"; exit 2; }
p_lines=$(grep -E '^\[ "\$gh" = 1 \] && sign_args\+=|^P=\(|^tagger=\$\(git config kuicksilver.privacy.tagger|^tag_id=\(' "$root/tools/release/local-release.sh")
[ "$(wc -l <<< "$p_lines" | tr -d ' ')" = 4 ] || { echo "FAIL: the Gradle arguments of local-release.sh not found"; exit 2; }
tail_run() { # <dir> <version> <attack: none|unsigned-sbom|commit-zone|home-swift-repo>: the tail on <dir>/m2, output in $tail_out
  local d="$1"
  mkdir -p "$d/out/logs"; printf 'x' > "$d/x"; (cd "$d" && zip -q out/Kuicksilver.xcframework.zip x)
  mkdir -p "$d/src"; for f in openssl-4.1.0.tar.gz openssl-4.1.0.tar.gz.asc zlib-1.4.tar.gz zlib-1.4.tar.gz.asc brotli-1.2.1.tar.gz; do printf 's' > "$d/src/$f"; done
  git init -q --bare -b main "$d/swift.git"
  if [ "$3" = home-swift-repo ]; then   # the package repository already holds a file naming a home directory
    ( git init -q -b main "$d/seed" && cd "$d/seed" && printf 'built in /Users/someone/src\n' > NOTES && git add NOTES \
      && TZ=UTC git -c user.email=t@example.invalid -c user.name=t commit -q -m seed && git push -q "$d/swift.git" main ) || exit 2
  fi
  tail_out=$(cd "$root" && GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=kuicksilver.privacy.tagger GIT_CONFIG_VALUE_0="Kuicksilver <hello@kuicksilver.io>" KSL_SWIFT_REPO="$d/swift.git" TL="$d" V="$2" ATTACK="$3" MODE="${TAIL_MODE:-github}" bash -c '
  set -euo pipefail
  version=$V; out=$TL/out; logs=$out/logs; m2=$TL/m2; signed=1; dry=0; problems=0; n=0; started=1794688855
  if [ "$MODE" = central ]; then gh=0; central_pre=1; given="$V --central-prerelease"; else gh=1; central_pre=0; given="$V --github-prerelease"; fi
  src_dir=$TL/src; stamp=$TL/none.stamp; xcf=$out/Kuicksilver.xcframework.zip; push_branch=main
  head=$(git rev-parse HEAD); short=$(git rev-parse --short=7 HEAD); xcf_sum=$(shasum -a 256 "$xcf" | cut -d" " -f1)
  # an explicit zone in the environment overrides TZ for git
  [ "$ATTACK" = commit-zone ] && export GIT_AUTHOR_DATE="2026-11-15T10:00:00+0500" GIT_COMMITTER_DATE="2026-11-15T10:00:00+0500"
  sha() { shasum -a 256 "$@" | cut -d" " -f1; }
  step() { local name="$1" log; shift; n=$((n+1)); log="$logs/$(printf %02d $n).log"; printf "[%2d] %s " "$n" "$name"
    if "$@" > "$log" 2>&1; then echo ok; else echo FAIL; tail -5 "$log"; exit 1; fi; }
  gradle() { printf "%s\n" "$*" >> "$TL/tasks"; local a f
    for a in "$@"; do case "$a" in
      sbomZip) (cd "$TL" && printf "{}" > bom.json && zip -q "$out/kuicksilver-$version-sbom.zip" bom.json) ;;
      # the Central upload: the portal that times out on a large bundle
      publishToMavenCentral) if [ "$ATTACK" = upload-408 ]; then echo "Upload failed: 408 Request Timeout"; return 1; fi ;;
      -Pkuicksilver.release.sign=*) for f in $(tr , " " <<< "${a#*=}"); do
        # the signing that leaves one file unsigned
        [ "$ATTACK" = unsigned-sbom ] && [ "$f" = "$out/kuicksilver-$version-sbom.zip" ] && continue
        printf -- "-----BEGIN PGP SIGNATURE-----\n\nc2ln\n-----END PGP SIGNATURE-----\n" > "$f.asc"; done ;;
    esac; done; }
  bash() { if [ "$1" = tools/release/verify-signature.sh ]; then echo "OK (stub)"; else command bash "$@"; fi; }
  G=(gradle); sign_args=()
  '"$p_lines"'
  '"$tail_block"'
  ' 2>&1); tail_rc=$?
  tail_central=$(sed 's/-x publishToMavenCentral//g' "$d/tasks" 2>/dev/null | grep -c publishToMavenCentral || true)
}
tail_attack() { # <label> <pattern of the refusal> <dir> <version> <attack>: the run must fail, before anything is printed to publish
  local label="$1" pat="$2"; shift 2
  tail_run "$@"
  if [ "$tail_rc" != 0 ] && grep -qE -- "$pat" <<< "$tail_out" && ! grep -q 'gh release create' <<< "$tail_out" && [ "$tail_central" = 0 ]; then
    pass=$((pass+1)); echo "ok   $label"
  else fail=$((fail+1)); echo "FAIL $label: rc=$tail_rc central=$tail_central"; printf '%s\n' "$tail_out" | tail -8 | sed 's/^/     | /'; fi
}
# the run as it should go, in a +0500 zone and with a stray file next to the assets (it is no asset)
tl="$tmp/tail"; mk_m2 "$tl/m2" signed; mkdir -p "$tl/out"; printf 'stray' > "$tl/out/kuicksilver-$V-extra.zip"
TZ=Asia/Yekaterinburg tail_run "$tl" "$V" none
L="github prerelease: the end of a run (I1 no upload, I2 assets signed and listed, I3 UTC)"
printed=$(sed -n '/gh release create/,/swift-package-check.sh remote/p' <<< "$tail_out" | tr ' ' '\n' | grep "^$tl/out/" | sort -u)
expect=$(for f in "kuicksilver-$V-maven-repository.zip" "kuicksilver-$V-maven-repository.md" "kuicksilver-$V-sbom.zip" \
    "kuicksilver-$V.intoto.jsonl" Kuicksilver.xcframework.zip "kuicksilver-$V-SHA256SUMS"; do echo "$tl/out/$f"; echo "$tl/out/$f.asc"; done | sort)
sums=$(awk '{print $2}' "$tl/out/kuicksilver-$V-SHA256SUMS" 2>/dev/null | sort)
want=$(sed 's|.*/||' <<< "$expect" | grep -vE -- '-SHA256SUMS(\.asc)?$' | sort)
bad=""; while read -r f; do [ -s "$f" ] || bad="$bad missing:$f"; done <<< "$expect"
if [ "$tail_rc" = 0 ] && [ -z "$bad" ] && [ "$printed" = "$expect" ] && [ "$sums" = "$want" ] \
    && [ "$tail_central" = 0 ] && [ "$(grep -c . "$tl/tasks")" = "$(grep -c -- '-PmavenCentralUsername= -PmavenCentralPassword= -x publishToMavenCentral' "$tl/tasks")" ] \
    && grep -q -- '--draft --prerelease' <<< "$tail_out" && grep -qx '       export TZ=UTC' <<< "$tail_out" \
    && grep -qF 'git -c user.name=Kuicksilver -c user.email=hello@kuicksilver.io tag -s v'"$V" <<< "$tail_out" \
    && grep -q 'swift package: UTC dates, no home-directory path ok' <<< "$tail_out" \
    && [ "$(git -C "$tl/out/kuicksilver-swift" log -1 --format='%ad %cd' --date=format:%z)" = "+0000 +0000" ]; then
  pass=$((pass+1)); echo "ok   $L"
else fail=$((fail+1)); echo "FAIL $L: rc=$tail_rc central=$tail_central bad=$bad"; printf '%s\n' "$tail_out" | tail -15 | sed 's/^/     | /'; fi
# the attacks
a="$tmp/attack-unsigned"; mk_m2 "$a/m2" signed
tail_attack "negative_tailUnsignedAsset (I2)"        "sbom.zip.asc is missing in a signed run" "$a" "$V" unsigned-sbom
a="$tmp/attack-stray"; mk_m2 "$a/m2" signed; printf 'x' > "$a/m2/io/kuicksilver/kuicksilver-bom/$V/notes.txt"
tail_attack "negative_tailUnsignedFileInPublication (I2)" "no signature notes.txt.asc" "$a" "$V" none
a="$tmp/attack-zone"; mk_m2 "$a/m2" signed
tail_attack "negative_tailSwiftCommitZone (I3)"      "zones [+]0500 [+]0500"            "$a" "$V" commit-zone
a="$tmp/attack-home-swift"; mk_m2 "$a/m2" signed
tail_attack "negative_tailHomePathInSwiftPackage (I3)" "names a home directory"         "$a" "$V" home-swift-repo
a="$tmp/attack-home-pom"; mk_m2 "$a/m2" signed
printf '<project><url>file:/home/someone/kuicksilver</url></project>\n' > "$a/m2/io/kuicksilver/kuicksilver-bom/$V/kuicksilver-bom-$V.pom"
tail_attack "negative_tailHomePathInPom (I3)"         "privacy: no home-directory path in the repository zip FAIL" "$a" "$V" none
a="$tmp/attack-final"; V=0.4.0 mk_m2 "$a/m2" signed
tail_attack "negative_tailFinalVersion"               "is not a prerelease"              "$a" 0.4.0 none

# --central-prerelease: the same end of a run on a fixture publication, with the upload to Central (a stub) and the
# prerelease's next steps: the Swift package checked against the local zip before Publish, the tag only after it, the
# GitHub release a draft prerelease with the source tarballs attached, the site of the prerelease. A failed upload (the
# portal's 408) still prints them, with the browser upload of the bundle in front, and the run fails.
cl="$tmp/central"; mk_m2 "$cl/m2" signed; TAIL_MODE=central tail_run "$cl" "$V" none
L="central prerelease: the end of a run (one upload, the prerelease's next steps in order)"
order_ok=$(awk '/swift-package-check.sh local/ {a=NR} /Press Publish/ {b=NR} /consumer-smoke.sh --central/ {c=NR} / tag -s v/ {d=NR}
  /gh release create/ {e=NR} /gh workflow run pages -f version=/ {f=NR} END {print (a && a<b && b<c && c<d && d<e && e<f) ? "yes" : "no"}' <<< "$tail_out")
if [ "$tail_rc" = 0 ] && [ "$tail_central" = 1 ] && [ "$order_ok" = yes ] && grep -q -- '--draft --prerelease' <<< "$tail_out" \
    && grep -q "$cl/src/openssl-4.1.0.tar.gz $cl/src/openssl-4.1.0.tar.gz.asc" <<< "$tail_out" && grep -q "$cl/src/brotli-1.2.1.tar.gz" <<< "$tail_out" \
    && ! grep -q 'Publish Component' <<< "$tail_out"; then
  pass=$((pass+1)); echo "ok   $L"
else fail=$((fail+1)); echo "FAIL $L: rc=$tail_rc central=$tail_central order=$order_ok"; printf '%s\n' "$tail_out" | tail -30 | sed 's/^/     | /'; fi
c4="$tmp/central-408"; mk_m2 "$c4/m2" signed; TAIL_MODE=central tail_run "$c4" "$V" upload-408
L="negative_centralUploadFails: the next steps are printed with the browser upload, the run fails"
if [ "$tail_rc" != 0 ] && grep -q 'Publish Component' <<< "$tail_out" && grep -q "io.kuicksilver-$V-\*.zip" <<< "$tail_out" \
    && grep -q ' tag -s v' <<< "$tail_out" && grep -q 'swift-package-check.sh local' <<< "$tail_out"; then
  pass=$((pass+1)); echo "ok   $L"
else fail=$((fail+1)); echo "FAIL $L: rc=$tail_rc"; printf '%s\n' "$tail_out" | tail -20 | sed 's/^/     | /'; fi

# the repository's own version files, so a pattern that drifts from their real layout is caught: the tree passes for the
# version of its fallbacks, except that before the release commit the README's status line names the last published
# version ("X.Y.Z is on Maven Central") while its dependency blocks, docs/install.md and the iOS guide already name the line's version;
# with no published version to name (0.2.x are withdrawn) only the "release in preparation" note remains
new_repo "$tmp/real"
for f in build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts build-logic/src/main/kotlin/kuicksilver.release.gradle.kts \
    kuicksilver-bom/build.gradle.kts samples/realtime-telemetry/build.gradle.kts samples/ios/shared/build.gradle.kts \
    samples/ios/kuicksilver-swift/build.gradle.kts samples/compose-demo/build.gradle.kts samples/kq-cli/build.gradle.kts \
    tools/check/consumer-smoke.sh README.md docs/install.md docs/guide/ios.md docs/guide/quickstart.md; do
  mkdir -p "$(dirname "$f")"; cp "$root/$f" "$f" || { echo "FAIL: $f is gone from the repository"; exit 2; }
done
line=$(sed -n 's/.*getOrElse("\([0-9]*\.[0-9]*\.[0-9]*\)-SNAPSHOT").*/\1/p' build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts)
published=$(grep -v 'Until [0-9.]* is on Maven Central' README.md \
  | sed -n 's/.* \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\) is on Maven Central.*/\1/p' | head -1)
printf '# Changelog\n\n## [%s] - 2026-01-01\n' "$line" > CHANGELOG.md; git add -A; git commit -qm real
# before the release the README names both versions, and the README and docs/install.md call the line's version the release
# in preparation
prep=$(printf 'README.md still calls %s the release in preparation\ndocs/install.md still calls %s the release in preparation\ndocs/guide/quickstart.md still calls %s the release in preparation' "$line" "$line" "$line")
want=""; if [ -z "$published" ]; then want="$prep"
elif [ "$published" != "$line" ]; then want=$(printf 'README.md names %s instead of %s\n%s' \
  "$(printf '%s\n%s\n' "$published" "$line" | sort -u | tr '\n' ' ' | sed 's/ $//')" "$line" "$prep"); fi
want=$(grep . <<< "$want" | sort)
out=$(bash tools/release/local-release.sh "$line" --dry-run 2>&1)
have=$(grep 'WARN' <<< "$out" | sed -e 's/^ *WARN (a release would refuse): //' -e 's/ (the commit that prepares.*//' -e 's/ ("release in preparation".*//' | sort)
if [ -n "$line" ] && [ "$have" = "$want" ]; then verdict=ok; pass=$((pass+1)); else verdict=FAIL; fail=$((fail+1)); fi
printf '%-4s %-58s line=%s published=%s | %s\n' "$verdict" "the repository's own version files" "$line" "$published" "$(tr '\n' ' ' <<< "${have:-no warning}")"
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
