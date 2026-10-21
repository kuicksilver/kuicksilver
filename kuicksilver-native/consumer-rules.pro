# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
#
# Consumer keep rules, published in the AAR as proguard.txt: an app that shrinks with R8 applies them to this library.
# JNI_OnLoad (src/jni/ksl_jni.c) looks these names up at run time, and fails the whole System.loadLibrary("ksl") when one
# is missing, so TLS and QUIC would be unavailable in a minified release build:
# - RegisterNatives binds every native method of KslNative by name and descriptor; a native the app never reaches would
#   otherwise be removed, and a missing one fails the registration of all of them (JNI spec: NoSuchMethodError);
# - the descriptors of udpSend/udpRecv name io.kuicksilver.native.PacketBuffer (includedescriptorclasses keeps that name);
# - FindClass("io/kuicksilver/native/PacketBuffer") and GetFieldID(..., "buffer", "Ljava/nio/ByteBuffer;").
# tools/check/android-keep-rules.sh checks the built AAR against this list; keep it in step with ksl_jni.c.
-keep,includedescriptorclasses class io.kuicksilver.native.KslNative {
    native <methods>;
}
-keep class io.kuicksilver.native.PacketBuffer {
    java.nio.ByteBuffer buffer;
}
