#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Checks what tools/fuzz/reproducers.txt records about each fuzz reproducer (tools/check/reproducers.py checks its form):
# in a copy of the tree (build/reproducers/tree: tracked and untracked files that are not ignored), every input and
# every guard test first passes as the tree is; then each plant (tools/fuzz/plants/<name>.patch, the guarded fix put
# back) is applied in turn, and with it
#   a live input fails, with the recorded piece of its failure in the message;
#   a dead input still passes (when it fails again, the entry says dead wrongly: record it live);
#   every guard test of the entry fails (a guard that passes with the bug back guards nothing).
# Each input runs as its Jazzer target runs it in the JVM tests (regression mode): it is copied into the target's
# regression directory under a name of its own (zz-reproducer-<n>), so a committed corpus input runs the same way; an
# input of the ksl harness (tools/fuzz/corpus/ksl.parsers) runs through tools/fuzz/ksl/build.sh's binary built from the
# planted copy (-runs=0, as tools/c-test.sh replays the corpus), its output being the failure text. The
# plant is removed again before the next one. Kotlin warnings do not fail the planted build (a plant may leave a
# parameter unused). Takes a few minutes per plant (an incremental build of the planted module and its tests).
# Usage: tools/fuzz/reproducers-verify.sh [plant-name...]   (only the entries of those plants; exit 1 on any mismatch)
#        Gradle: ~/.kuicksilver-tools/quiet-gradle when present, else ./gradlew --max-workers=2; KSL_GRADLE_ARGS adds
#        arguments, e.g. "--offline -Pkuicksilver.openssl.prebuilt=true"
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$root/build/reproducers"
copy="$work/tree"
plan="$work/plan.json"
mkdir -p "$work"
python3 -I "$root/tools/check/reproducers.py" "$root" --plan > "$plan" || {
  python3 -I "$root/tools/check/reproducers.py" "$root" >&2 || true
  echo "reproducers-verify: the manifest has findings (above); fix them first" >&2
  exit 1
}
rm -rf "$copy"; mkdir -p "$copy"
(cd "$root" && git ls-files -z --cached --others --exclude-standard) | (cd "$root" && rsync -a --from0 --files-from=- ./ "$copy/")
for f in local.properties samples/compose-demo/local.properties; do [ ! -f "$root/$f" ] || cp "$root/$f" "$copy/$f"; done
[ ! -d "$root/build/openssl" ] || { mkdir -p "$copy/build"; cp -R "$root/build/openssl" "$copy/build/"; }
if [ -x "$HOME/.kuicksilver-tools/quiet-gradle" ]; then g=("$HOME/.kuicksilver-tools/quiet-gradle"); else g=(./gradlew --max-workers=2); fi

# the work list: one round without a plant, then one per plant (only those named on the command line)
python3 -I - "$plan" "$copy" "$work/rounds.json" "$@" <<'PY'
import json, os, shutil, sys
plan, copy, out, only = sys.argv[1], sys.argv[2], sys.argv[3], set(sys.argv[4:])
entries = json.load(open(plan))
if only:
    entries = [e for e in entries if os.path.basename(e["plant"])[:-len(".patch")] in only]
    missing = only - {os.path.basename(e["plant"])[:-len(".patch")] for e in entries}
    if missing:
        sys.exit("reproducers-verify: no entry uses the plant(s) " + ", ".join(sorted(missing)))
for i, e in enumerate(entries):
    module, cls, method, kind = e["target"]
    e["case"] = f"zz-reproducer-{i}"
    if kind == "c":  # the ksl harness replays a directory: one of its own per input
        d = os.path.join(copy, "build", "reproducers-c", e["case"])
    else:
        d = os.path.join(copy, module, "src/jvmTest/resources", *cls.split(".")[:-1], cls.split(".")[-1] + "Inputs", method)
    os.makedirs(d, exist_ok=True)
    shutil.copyfile(os.path.join(copy, e["input"]), os.path.join(d, e["case"]))
rounds = [{"plant": None, "entries": entries}]
for p in sorted({e["plant"] for e in entries}):
    rounds.append({"plant": p, "entries": [e for e in entries if e["plant"] == p]})
json.dump(rounds, open(out, "w"), indent=1)
PY

bad=0
n=$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$work/rounds.json")
for ((r = 0; r < n; r++)); do
  plant=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[int(sys.argv[2])]["plant"] or "")' "$work/rounds.json" "$r")
  # the Gradle tasks of the round: each module's jvmTest with the targets and guard tests of its entries
  args=()
  while IFS= read -r line; do args+=("$line"); done < <(python3 -I - "$work/rounds.json" "$r" <<'PY'
import json, sys
rnd = json.load(open(sys.argv[1]))[int(sys.argv[2])]
tests = {}
for e in rnd["entries"]:
    module, cls, method, kind = e["target"]
    tests.setdefault(module, set())
    if kind != "c":
        tests[module].add(f"{cls}.{method}")
    for gname in e["guards"]:
        tests[module].add(gname)  # a guard runs in the module of its input (the lint checks it is a test there)
for module in sorted(m for m in tests if tests[m]):
    print(f":{module}:jvmTest")
    for t in sorted(tests[module]):
        print("--tests"); print(t)
PY
  )
  # the copy lies inside the checkout: git must not take it for part of that repository, or it would patch the checkout
  if [ -n "$plant" ]; then (cd "$copy" && GIT_CEILING_DIRECTORIES="$work" git apply "$plant") || { echo "FAIL $plant: does not apply"; bad=1; continue; }; fi
  find "$copy" -path '*/build/test-results/jvmTest/*.xml' -delete 2>/dev/null || true
  # shellcheck disable=SC2086 # KSL_GRADLE_ARGS is a list of arguments
  if [ "${#args[@]}" -gt 0 ]; then
    (cd "$copy" && "${g[@]}" ${KSL_GRADLE_ARGS:-} -Pkuicksilver.warningsAsErrors=false --continue "${args[@]}") > "$work/gradle-$r.log" 2>&1 || true
  fi
  # inputs of the ksl harness (tools/fuzz/corpus/ksl.parsers): built from the planted copy, each replayed once as
  # tools/c-test.sh replays the corpus; its exit status and output are the result
  rm -rf "$copy/build/reproducers-c-results"; mkdir -p "$copy/build/reproducers-c-results"
  if ls "$copy/build/reproducers-c" >/dev/null 2>&1 && python3 -I -c 'import json,sys; sys.exit(0 if any(e["target"][3] == "c" for e in json.load(open(sys.argv[1]))[int(sys.argv[2])]["entries"]) else 1)' "$work/rounds.json" "$r"; then
    if (cd "$copy" && bash tools/fuzz/ksl/build.sh) > "$work/ksl-build-$r.log" 2>&1; then
      for d in "$copy"/build/reproducers-c/*/; do
        c=$(basename "$d")
        # from a directory of its own: the harness writes a crash-<hash> artifact into its working directory
        if (cd "$copy/build/reproducers-c-results" && "$copy/build/fuzz-ksl/ksl_fuzz" -runs=0 -timeout=60 "$d") > "$copy/build/reproducers-c-results/$c.log" 2>&1; then
          echo pass > "$copy/build/reproducers-c-results/$c.status"
        else
          echo fail > "$copy/build/reproducers-c-results/$c.status"
        fi
      done
    else
      echo "FAIL: the ksl harness did not build (see $work/ksl-build-$r.log)"; bad=1
    fi
  fi
  python3 -I - "$copy" "$work/rounds.json" "$r" "$work/gradle-$r.log" <<'PY' || bad=1
import glob, html, json, os, re, sys
copy, rounds, r, log = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
rnd = json.load(open(rounds))[r]
plant = rnd["plant"]
results = {}  # (class, case) -> failure text or None
for f in glob.glob(os.path.join(copy, "*", "build", "test-results", "jvmTest", "*.xml")):
    for m in re.finditer(r'<testcase name="([^"]*)" classname="([^"]*)"[^>]*?(/>|>(.*?)</testcase>)', open(f).read(), re.S):
        body = m.group(4) or ""
        fail = re.search(r'<(failure|error)\b([^>]*)>(.*?)</\1>', body, re.S) or re.search(r'<(failure|error)\b([^>]*)/>', body)
        name = html.unescape(m.group(1))
        results[(m.group(2), re.sub(r"\[jvm\]$", "", name).removesuffix("()"))] = \
            html.unescape(fail.group(2) + (fail.group(3) if fail.lastindex >= 3 else "")) if fail else None
for f in glob.glob(os.path.join(copy, "build", "reproducers-c-results", "*.status")):
    case = os.path.basename(f)[:-len(".status")]
    failed = open(f).read().strip() == "fail"
    results[("ksl_fuzz", case)] = open(f[:-len(".status")] + ".log", errors="replace").read() if failed else None
bad = 0
label = os.path.basename(plant)[:-len(".patch")] if plant else "no plant"
def say(ok, text):
    global bad
    bad += not ok
    print(("ok   " if ok else "FAIL ") + f"{label}: {text}")
for e in rnd["entries"]:
    cls = e["target"][1]
    got = results.get((cls, e["case"]), "absent")
    if got == "absent":
        say(False, f"{e['input']} did not run (see {log})")
    elif plant is None:
        say(got is None, f"{e['input']} passes as the tree is" + ("" if got is None else f": {got.strip()[:300]}"))
    elif e["state"] == "live":
        say(got is not None and e["expect"] in got,
            f"{e['input']} fails with '{e['expect']}'" + ("" if got is not None and e["expect"] in got else
                                                          f": {'it passes' if got is None else got.strip()[:300]}"))
    else:
        say(got is None, f"{e['input']} still passes (dead)" + ("" if got is None else
                                                                f": it fails again, record it live: {got.strip()[:300]}"))
    for gname in e["guards"]:
        gcls, gtest = gname.rsplit(".", 1)
        gres = results.get((gcls, gtest), "absent")
        if gres == "absent":
            say(False, f"guard {gname} did not run (see {log})")
        elif plant is None:
            say(gres is None, f"guard {gname} passes as the tree is")
        else:
            say(gres is not None, f"guard {gname} fails with the plant" + ("" if gres is not None else ": it passes"))
sys.exit(1 if bad else 0)
PY
  if [ -n "$plant" ]; then (cd "$copy" && GIT_CEILING_DIRECTORIES="$work" git apply -R "$plant"); fi
done
[ "$bad" = 0 ] && echo "reproducers-verify: every record holds" || echo "reproducers-verify: FAILED"
exit "$bad"
