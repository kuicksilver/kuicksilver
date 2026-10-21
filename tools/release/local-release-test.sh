#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The branch, CHANGELOG and version refusals of tools/release/local-release.sh (step 1), in a throwaway repository with
# main, two maintenance branches, a feature branch and an origin: the script runs as committed up to its local-gate check,
# where a stub line stops it (nothing is built, signed or uploaded). Each case expects "ok" or "refuse", optionally with a
# pattern its output must contain. Usage: local-release-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git init -q --bare "$tmp/origin.git"; git init -q -b main "$tmp/repo"; cd "$tmp/repo" || exit 2
git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false; git config core.hooksPath /dev/null
mkdir -p tools/release tools/check kuicksilver-native/src/c gradle
cp "$root/tools/check/llvm-tool.sh" tools/check/
cp "$root/kuicksilver-native/src/c/ksl.h" kuicksilver-native/src/c/; cp "$root/gradle/openssl.toml" gradle/
marker='^# the local gate: tools/ci/local-matrix.sh writes'
grep -qE "$marker" "$root/tools/release/local-release.sh" || { echo "FAIL: the local-gate marker line is gone from local-release.sh"; exit 2; }
awk -v m="$marker" '$0 ~ m {print "echo \"STOPPED-BEFORE-GATE push_branch=$push_branch problems=$problems\"; exit 0"} {print}' \
  "$root/tools/release/local-release.sh" > tools/release/local-release.sh
printf 'build/\n' > .gitignore

tree_version() { # <X.Y.Z of every -SNAPSHOT fallback> <version the README and the iOS guide name> [<file to leave behind>]
  local s="$1-SNAPSHOT" p="$2" f
  for f in build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts build-logic/src/main/kotlin/kuicksilver.release.gradle.kts \
      kuicksilver-bom/build.gradle.kts samples/realtime-telemetry/build.gradle.kts samples/ios/shared/build.gradle.kts \
      samples/ios/kuicksilver-swift/build.gradle.kts; do
    [ "$f" = "${3:-}" ] && continue
    mkdir -p "$(dirname "$f")"; printf 'version = providers.gradleProperty("kuicksilver.version").getOrElse("%s")\n' "$s" > "$f"
  done
  f=samples/ios/kuicksilver-swift/src/commonMain/kotlin/io/kuicksilver/swift/Kuicksilver.kt
  mkdir -p "$(dirname "$f")"; printf '    public const val VERSION: String = "%s"\n' "$s" > "$f"
  printf 'version="${1:-%s}"\n' "$s" > tools/check/consumer-smoke.sh
  mkdir -p docs/guide
  printf '> The API can change between any two 0.x releases, and %s is on Maven Central.\n\n    implementation("io.kuicksilver:kuicksilver-ktor-client:%s")\n' "$p" "$p" > README.md
  printf '        implementation("io.kuicksilver:kuicksilver-http3:%s")   // or -quic\n            url: "https://example.com/releases/%s/Kuicksilver.xcframework.zip",\n' "$p" "$p" > docs/guide/ios.md
}
commit() { git add -A; git commit -qm "$1"; }

# base: the 0.2.1 line prepared (the fork point of release/0.2.x); main then moves to 0.3.0
printf '# Changelog\n\n## [0.8.0] - 2027-06-01\n\n## [0.7.0] - 2027-05-01\n\n## [0.6.0] - 2027-04-01\n\n## [0.5.0] - 2027-03-01\n\n## [0.4.0-rc1] - 2027-02-01\n\n## [0.3.1] - 2027-01-15\n\n## [0.3.0] - 2026-12-01\n\n## [0.2.2] - 2026-11-25\n\n## [0.2.2-rc1] - 2026-11-20\n\n## [0.2.1] - 2026-11-03\n\n## [1.2.1] - 2027-01-01\n\n## [0.2.9] - unreleased\n\n## [0.2.8]\n' > CHANGELOG.md
tree_version 0.2.1 0.2.1; commit base
git remote add origin ../origin.git; git push -q origin main
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
git checkout -q main

pass=0; fail=0
t() { # <label> <ok|refuse>[:<pattern in the output>] <checkout target> <args...>
  local label="$1" exp="${2%%:*}" pat="" tgt="$3"; [ "$2" = "${2#*:}" ] || pat="${2#*:}"; shift 3
  git checkout -q $tgt || { echo "FAIL: checkout $tgt"; exit 2; }
  local out rc got verdict
  out=$(bash tools/release/local-release.sh "$@" 2>&1); rc=$?
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
t "release/0.2.x, 0.2.2-rc1 without the version bump"    "refuse:0.2.1-SNAPSHOT"        release/0.2.x 0.2.2-rc1
t "release/0.4.x, 0.4.0-rc1 (coordinates not checked)"   ok:push_branch=release/0.4.x   release/0.4.x 0.4.0-rc1
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
# dry runs: refusals are warnings
t "dry run: release/0.2.x, 0.3.0"                        "ok:WARN.*maintenance branch"  release/0.2.x 0.3.0 --dry-run
t "dry run: feature, 0.2.1"                              ok:WARN                        feature 0.2.1 --dry-run
t "dry run: main, 0.2.1 while release/0.2.x exists"      "ok:WARN.*release/0.2.x exists" main 0.2.1 --dry-run
t "dry run: release/0.2.x, 0.2.2 without the bump"       "ok:WARN.*0.2.1-SNAPSHOT"      release/0.2.x 0.2.2 --dry-run
git push -q origin release/0.2.x
t "release/0.2.x after push: no note"                    ok                             release/0.2.x 0.2.1
t "--release-commit pushed branch tip: no note"          ok                             "--detach $B" 0.2.1 --release-commit $B
# a maintenance branch only on origin counts as well
git push -q origin release/0.1.x:release/0.3.x; git fetch -q origin
t "main, 0.3.0 while origin/release/0.3.x exists"        "refuse:release/0.3.x exists"  main 0.3.0
git push -q origin :release/0.3.x; git fetch -q --prune origin
# CHANGELOG
t "CHANGELOG 0.2.9 - unreleased (placeholder)"           "refuse:no release date"       release/0.2.x 0.2.9
t "CHANGELOG [0.2.8] without date"                       "refuse:no release date"       release/0.2.x 0.2.8
t "CHANGELOG without 0.2.7"                              "refuse:has no '## \[0.2.7\]'" release/0.2.x 0.2.7
t "dry run: placeholder date (warning only)"             ok:WARN                        release/0.2.x 0.2.9 --dry-run
git checkout -q main
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
