# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
#
# Consumer keep rules, published in the AAR as proguard.txt.
# AsyncQlogSink's writer applies each queued operation to the application's sink in perform() and closes the traces left in
# closeLive(), never in its loop: ART 7.x aborted in the GC when a coroutine loop that called the application's classes was
# deoptimized (AsyncQlogSink.perform says why). An application's R8 may inline a private function with one caller back into
# that loop; a kept member is not inlined (renaming it, or removing it when unused, is fine).
-keepclassmembers,allowobfuscation,allowshrinking class io.kuicksilver.quic.qlog.AsyncQlogSink {
    private void perform(...);
    private void closeLive(...);
}
