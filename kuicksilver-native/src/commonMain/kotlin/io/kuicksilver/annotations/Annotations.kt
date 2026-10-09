// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.annotations

/** API that may change or be removed in a later release without a deprecation cycle. */
@RequiresOptIn(level = RequiresOptIn.Level.WARNING, message = "This API is experimental and may change.")
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
    AnnotationTarget.TYPEALIAS,
)
public annotation class ExperimentalKuicksilverApi

/** Internal to Kuicksilver modules; excluded from the public ABI and never stable. */
@RequiresOptIn(level = RequiresOptIn.Level.ERROR, message = "This API is internal to Kuicksilver.")
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
    AnnotationTarget.TYPEALIAS,
)
public annotation class InternalKuicksilverApi

/** Correct use needs care: custom verifiers, key logging, external signers. */
@RequiresOptIn(level = RequiresOptIn.Level.WARNING, message = "This API is delicate; read its documentation before use.")
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
    AnnotationTarget.TYPEALIAS,
)
public annotation class DelicateKuicksilverApi

/** Marker for Kuicksilver configuration DSLs. */
@DslMarker
@Target(AnnotationTarget.CLASS, AnnotationTarget.TYPE)
public annotation class KuicksilverDsl
