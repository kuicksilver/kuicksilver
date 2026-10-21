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
