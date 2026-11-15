#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs `./gradlew androidConnectedCheck` on the CI emulator, and once more only when the first run failed because a test
# APK could not be installed: ddmlib's "Failed to install-write all apks" after the `pm install-write` shell stream
# stalled (ShellCommandUnresponsiveException). Runs 40636584799, 40645584772 and 43654092978 (API 24): the device logged
# nothing for the 4 minutes of the upload and /data was 2% used, so the adb stream stalled; the APKs had not grown. Any
# other failure, and a second failure, fails the step. The tasks of the retried run are the same; only the install is the
# flaky part, and a test failure is never retried, also when an install stalled in the same run.
#
# Usage: tools/ci/android-connected-check.sh [gradle args...] (from the repository root)
set -uo pipefail
log=$(mktemp)
trap 'rm -f "$log"' EXIT
./gradlew --stacktrace androidConnectedCheck "$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
[ "$rc" -eq 0 ] && exit 0
if grep -q "Failed to install-write all apks" "$log" && grep -q "ShellCommandUnresponsiveException" "$log" &&
  ! grep -q "There were failing tests" "$log"; then
  echo "::warning::androidConnectedCheck: a test APK install stalled (ShellCommandUnresponsiveException); running it once more"
  adb shell df /data || true
  ./gradlew --stacktrace androidConnectedCheck "$@"
  exit $?
fi
exit "$rc"
