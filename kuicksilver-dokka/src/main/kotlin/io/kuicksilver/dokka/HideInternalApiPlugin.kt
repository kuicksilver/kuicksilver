// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.dokka

import org.jetbrains.dokka.base.DokkaBase
import org.jetbrains.dokka.base.transformers.documentables.SuppressedByConditionDocumentableFilterTransformer
import org.jetbrains.dokka.links.DRI
import org.jetbrains.dokka.model.Annotations
import org.jetbrains.dokka.model.DModule
import org.jetbrains.dokka.model.Documentable
import org.jetbrains.dokka.model.properties.WithExtraProperties
import org.jetbrains.dokka.plugability.DokkaContext
import org.jetbrains.dokka.plugability.DokkaPlugin
import org.jetbrains.dokka.plugability.DokkaPluginApiPreview
import org.jetbrains.dokka.plugability.PluginApiPreviewAcknowledgement

/**
 * Leaves every declaration annotated with `io.kuicksilver.annotations.InternalKuicksilverApi` (and everything inside it)
 * out of the API reference: that API is public only so Kuicksilver's own modules can share it, and it is never stable.
 *
 * Dokka's `suppressAnnotatedWith` source-set option does the same, but the Dokka Gradle plugin 2.2.0 does not expose it;
 * once it does, setting it to that annotation in the kmp convention plugin replaces this plugin.
 */
public class HideInternalApiPlugin : DokkaPlugin() {
    public val hideInternalApi by extending {
        plugin<DokkaBase>().preMergeDocumentableTransformer providing ::HideInternalApiTransformer
    }

    @DokkaPluginApiPreview
    override fun pluginApiPreviewAcknowledgement(): PluginApiPreviewAcknowledgement = PluginApiPreviewAcknowledgement
}

/**
 * Suppresses the declarations whose own annotations include `InternalKuicksilverApi`, and every declaration of another
 * source set with the same identity (an `actual` whose `expect` is annotated, the copy of a declaration in a source set
 * where the annotation did not resolve). The annotation is matched by its simple name when its package is unknown.
 */
public class HideInternalApiTransformer(
    context: DokkaContext,
) : SuppressedByConditionDocumentableFilterTransformer(context) {
    private var hidden: Set<DRI> = emptySet()

    override fun invoke(modules: List<DModule>): List<DModule> {
        val found = HashSet<DRI>()

        fun visit(d: Documentable) {
            if (annotated(d)) found += d.dri
            d.children.forEach(::visit)
        }
        modules.forEach(::visit)
        hidden = found
        return super.invoke(modules)
    }

    override fun shouldBeSuppressed(d: Documentable): Boolean = d.dri in hidden || annotated(d)

    private fun annotated(d: Documentable): Boolean =
        (d as? WithExtraProperties<*>)
            ?.extra
            ?.allOfType<Annotations>()
            ?.flatMap { it.directAnnotations.values.flatten() }
            ?.any {
                it.dri.classNames == ANNOTATION_NAME && (it.dri.packageName == ANNOTATION_PACKAGE || it.dri.packageName.isNullOrEmpty())
            }
            ?: false

    private companion object {
        const val ANNOTATION_PACKAGE = "io.kuicksilver.annotations"
        const val ANNOTATION_NAME = "InternalKuicksilverApi"
    }
}
