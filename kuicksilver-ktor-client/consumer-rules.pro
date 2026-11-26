# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
#
# Consumer keep rules, published in the AAR as proguard.txt and in the JVM jar as META-INF/proguard/kuicksilver-ktor-client.pro.
# HttpClient() finds this engine through ServiceLoader (META-INF/services/io.ktor.client.HttpClientEngineContainer), which
# instantiates the container by name: a shrinker that does not see the lookup would remove or rename the class, and the
# services entry with it, and HttpClient() would silently pick another engine.
# tools/check/service-keep-rules.sh checks that every class named in META-INF/services is kept.
-keep class io.kuicksilver.ktor.client.KuicksilverEngineContainer {
    public <init>();
}

# The ALTSVC frame learner (KuicksilverEngine.learnAltSvcFrames, its KDoc says why) keeps its work in these helpers so that
# the coroutine's loop makes no call through an interface: ART 7.x aborted in the GC when that loop was deoptimized. An
# application's R8 may inline a private function with one caller and bring those calls back into the loop; a kept member is
# not inlined (renaming it, or removing it when unused, is fine). tools/check/r8-inlining.sh checks that an app's R8 keeps
# each one called, not inlined.
-keepclassmembers,allowobfuscation,allowshrinking class io.kuicksilver.ktor.client.KuicksilverEngine {
    private *** takeAltSvcFrames();
    private *** learnAltSvcFrameBatch(...);
    private *** finishAltSvcFrames(...);
}

# The engine's event listener and logger are called in EngineEvents.deliver, never in a caller's coroutine loop (EngineEvents.emit
# says why: ART 7.x). An application's R8 inlines it back into those loops (R8 9.3 does); kept, it does not.
-keepclassmembers,allowobfuscation,allowshrinking class io.kuicksilver.ktor.client.EngineEvents {
    *** deliver(...);
}

