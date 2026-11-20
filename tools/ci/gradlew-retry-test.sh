#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests gradlew-retry.sh with a fake ./gradlew: one more run, with --refresh-dependencies and the same arguments, only
# after a dependency was not found or not downloaded and no test failed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fails=0
case_run() {   # case_run <name> <expected exit> <expected runs> <outputs, one per run: ok|module|file|get|crlf|tests|both|method>
  local name=$1 want_rc=$2 want_runs=$3
  shift 3
  local dir
  dir=$(mktemp -d)
  printf '%s\n' "$@" > "$dir/plan"
  cat > "$dir/gradlew" <<'G'
#!/usr/bin/env bash
n=$(( $(cat runs 2>/dev/null || echo 0) + 1 )); echo $n > runs
echo "$*" >> args
case $(sed -n "${n}p" plan) in
  ok) echo "BUILD SUCCESSFUL"; exit 0 ;;
  module) echo "   > Could not find io.ktor:ktor-server-core:3.6.1."; exit 1 ;;
  file) echo "   > Could not find jose4j-0.9.6.jar (org.bitbucket.b_c:jose4j:0.9.6)."; exit 1 ;;
  get) echo "   > Could not GET 'https://repo.maven.apache.org/maven2/a/b/1/b-1.pom'. Received status code 502 from server"; exit 1 ;;
  crlf) printf '   > Could not find org.jetbrains.kotlin:kotlin-stdlib:2.4.0.\r\n'; exit 1 ;;
  both) echo "   > Could not find io.ktor:ktor-server-core:3.6.1."; echo "> There were failing tests. See the report at: x"; exit 1 ;;
  method) echo "> Could not find method implementation() for arguments [x] on object of type Foo."; exit 1 ;;
  *) echo "> There were failing tests. See the report at: x"; exit 1 ;;
esac
G
  chmod +x "$dir/gradlew"
  local rc=0
  (cd "$dir" && KSL_GRADLE_RETRY_DELAY=0 bash "$here/gradlew-retry.sh" --stacktrace :a:b > out.log 2>&1) || rc=$?
  local runs want_args
  runs=$(cat "$dir/runs")
  want_args=$'--stacktrace :a:b'; [ "$want_runs" -lt 2 ] || want_args+=$'\n--refresh-dependencies --stacktrace :a:b'
  if [ "$rc" -ne "$want_rc" ] || [ "$runs" -ne "$want_runs" ] || [ "$(cat "$dir/args")" != "$want_args" ]; then
    echo "FAIL $name: exit $rc (want $want_rc), runs $runs (want $want_runs), arguments: $(tr '\n' '|' < "$dir/args")"
    fails=$((fails + 1))
  else
    echo "ok $name"
  fi
  rm -rf "$dir"
}
case_run "a passing run is not repeated" 0 1 ok
case_run "a module not found runs once more, refreshed" 0 2 module ok
case_run "a file of a found module not found runs once more" 0 2 file ok
case_run "a failed GET runs once more" 0 2 get ok
case_run "a Windows line end still counts" 0 2 crlf ok
case_run "the second failure fails the step" 1 2 file file
case_run "negative_aFailingTestIsNeverRetried" 1 1 tests ok
case_run "negative_aFailingTestNextToAMissingModuleIsNeverRetried" 1 1 both ok
case_run "negative_aBuildScriptErrorIsNotADownload" 1 1 method ok
[ "$fails" -eq 0 ] || { echo "$fails case(s) failed"; exit 1; }
echo "gradlew-retry: all cases passed"
