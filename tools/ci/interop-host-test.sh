#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests interop-host.sh tshark with stubs for sudo, curl, gpg, apt-get, apt-cache, tshark and sleep: a PPA that answers 503
# (apt-get update exits 0 with Ubuntu's 4.2 as the candidate, or an install that exits 100) is tried again with a doubling
# pause, never installs Ubuntu's 4.2, and fails with a clear message once the attempts are spent.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fails=0
# case_run <name> <expected exit> <expected update runs> <expected sleeps> <plan, one word per apt-get update: ppa | noppa |
# fail | ppa-install-fails | acfail (apt-cache policy fails)>
case_run() {
  local name=$1 want_rc=$2 want_updates=$3 want_sleeps=$4
  shift 4
  local dir rc=0
  dir=$(mktemp -d)
  mkdir -p "$dir/bin"
  printf '%s\n' "$@" > "$dir/plan"
  cat > "$dir/bin/sudo" <<'S'
#!/usr/bin/env bash
case $1 in install|chmod) exit 0 ;; tee) cat > /dev/null; exit 0 ;; esac   # nothing is written under /etc
while [[ $1 == *=* ]]; do export "${1?}"; shift; done
exec "$@"
S
  cat > "$dir/bin/curl" <<'S'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do [ "$1" = -o ] && { echo key > "$2"; shift; }; shift; done
S
  cat > "$dir/bin/gpg" <<'S'
#!/usr/bin/env bash
case "$*" in *--show-keys*) echo "pub:-:4096:1:D875551314ECA0F0:"; echo "fpr:::::::::A2E402B85A4B70CD78D8A3D9D875551314ECA0F0:" ;; *) cat ;; esac
S
  cat > "$dir/bin/apt-get" <<'S'
#!/usr/bin/env bash
echo "apt-get $*" >> "$T/calls"
case " $* " in
  *" update "*)
    n=$(( $(cat "$T/updates" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$T/updates"
    step=$(sed -n "${n}p" "$T/plan"); echo "$step" > "$T/step"
    case $step in fail) exit 100 ;; *) exit 0 ;; esac ;;
  *" install "*)
    [ "$(cat "$T/step")" = ppa-install-fails ] && { echo "E: Failed to fetch https://ppa.launchpadcontent.net/... 503"; exit 100; }
    for a in "$@"; do case $a in tshark=*) echo "${a#tshark=}" > "$T/installed" ;; tshark) echo unpinned > "$T/installed" ;; esac; done
    exit 0 ;;
esac
S
  cat > "$dir/bin/apt-cache" <<'S'
#!/usr/bin/env bash
case $(cat "$T/step") in
  acfail) echo "E: the package cache is broken" >&2; exit 100 ;;
  ppa|ppa-install-fails) c=4.6.1-1~ubuntu24.04.0~ppa1 ;;
  *) c=4.2.2-1.1build3 ;;
esac
printf 'tshark:\n  Installed: (none)\n  Candidate: %s\n' "$c"
S
  cat > "$dir/bin/tshark" <<'S'
#!/usr/bin/env bash
case $(cat "$T/installed" 2>/dev/null) in 4.6.1*) echo "TShark (Wireshark) 4.6.1." ;; *) echo "TShark (Wireshark) 4.2.2." ;; esac
S
  # shellcheck disable=SC2016 # the stubs expand their own variables
  printf '#!/usr/bin/env bash\necho "$1" >> "$T/sleeps"\n' > "$dir/bin/sleep"; : > "$dir/sleeps"
  printf '#!/usr/bin/env bash\necho 4.6.1-1\n' > "$dir/bin/dpkg-query"
  chmod +x "$dir/bin/"*
  (cd "$dir" && T="$dir" PATH="$dir/bin:$PATH" GITHUB_STEP_SUMMARY="" KSL_INTEROP_APT_DELAY=30 \
    bash "$here/interop-host.sh" tshark jq > out.log 2>&1) || rc=$?
  local updates sleeps installed
  updates=$(cat "$dir/updates" 2>/dev/null || echo 0)
  sleeps=$(tr '\n' ' ' < "$dir/sleeps" | sed 's/ $//')
  installed=$(cat "$dir/installed" 2>/dev/null || echo none)
  local bad=""
  [ "$rc" -eq "$want_rc" ] || bad+=" exit $rc (want $want_rc);"
  [ "$updates" -eq "$want_updates" ] || bad+=" updates $updates (want $want_updates);"
  [ "$sleeps" = "$want_sleeps" ] || bad+=" sleeps '$sleeps' (want '$want_sleeps');"
  # never an unpinned install, never Ubuntu's 4.2
  [ "$installed" = none ] || [ "$installed" = 4.6.1-1~ubuntu24.04.0~ppa1 ] || bad+=" installed '$installed';"
  if [ "$want_rc" -eq 0 ]; then
    grep -q 'TShark (Wireshark) 4.6.1' "$dir/out.log" || bad+=" no 4.6.1 in the output;"
    grep -q 'install -y -q --no-install-recommends tshark=4.6.1-1~ubuntu24.04.0~ppa1 python3-venv jq' "$dir/calls" || bad+=" install not pinned to the PPA version;"
  else
    grep -q '::error::tshark 4.5.0 or later could not be installed from the wireshark-dev/stable PPA' "$dir/out.log" || bad+=" no clear error;"
    [ "$installed" = none ] || bad+=" installed '$installed' although it failed;"
  fi
  if [ -n "$bad" ]; then echo "FAIL $name:$bad"; sed 's/^/    /' "$dir/out.log"; fails=$((fails + 1)); else echo "ok $name"; fi
  rm -rf "$dir"
}
case_run "the PPA answers: one update, one install, no pause" 0 1 "" ppa
case_run "negative_aPpaIndexNotFetchedNeverInstallsUbuntus42 (update exits 0, candidate 4.2.2)" 0 3 "30 60" noppa noppa ppa
case_run "an install that exits 100 (a .deb answered 503) is tried again" 0 2 "30" ppa-install-fails ppa
case_run "an update that fails is tried again" 0 2 "30" fail ppa
case_run "an apt-cache policy that fails is tried again, not a silent exit" 0 2 "30" acfail ppa
case_run "negative_anAptCacheThatKeepsFailingFailsClearly" 1 5 "30 60 120 240" acfail acfail acfail acfail acfail
case_run "negative_aPpaThatStaysDownFailsClearlyAfterFiveAttempts" 1 5 "30 60 120 240" noppa noppa noppa noppa noppa
case_run "negative_installFailuresToTheEndFailClearly" 1 5 "30 60 120 240" ppa-install-fails ppa-install-fails ppa-install-fails ppa-install-fails ppa-install-fails
[ "$fails" -eq 0 ] || { echo "$fails case(s) failed"; exit 1; }
echo "interop-host: all cases passed"
