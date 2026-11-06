// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import java.lang.reflect.Modifier
import java.util.IdentityHashMap

/**
 * The per-connection buffer inventory: a reflective walk of everything one connection object reaches that a second,
 * independent connection does not (configurations, the crypto provider, constants and classes are shared and left out), each
 * object charged to the first field path that reaches it, array indices folded. Sizes follow HotSpot's 64-bit layout with
 * compressed pointers (12-byte object header, 16-byte array header, 4-byte references, 8-byte alignment); Kotlin/Native's
 * arrays have the same payload. Fields the module system hides (inside `java.base` without `--add-opens`) count as shallow.
 */
internal object Footprint {
    /** Prints the paths holding the most bytes under [root], with a total, as `<bytes> <path> <type>[length]`. */
    fun report(label: String, root: Any, out: (String) -> Unit, shared: Any? = null, rows: Int = 30) {
        val sharedSet = IdentityHashMap<Any, Unit>()
        if (shared != null) walk(shared) { _, o, _ -> sharedSet[o] = Unit; o === shared || !isBoundary(o) }
        val byPath = HashMap<String, LongArray>()
        val types = HashMap<String, String>()
        var total = 0L
        walk(root) { path, o, _ ->
            if (o !== root && (sharedSet.containsKey(o) || isShared(o) || isBoundary(o))) return@walk false
            val size = shallow(o)
            total += size
            val key = path.ifEmpty { "<core>" }
            byPath.getOrPut(key) { LongArray(2) }.let { it[0] += size; it[1]++ }
            types.putIfAbsent(key, describe(o))
            true
        }
        out("$label inventory: $total B reachable and not shared, largest paths (bytes, objects, path, type):")
        for ((k, v) in byPath.entries.sortedByDescending { it.value[0] }.take(rows)) out("  ${v[0]} B  ${v[1]}  $k  ${types[k]}")
    }

    /**
     * Where a connection's graph joins the process's: the endpoint (it reaches every other connection), dispatchers and the
     * in-memory network. Not counted and not crossed.
     */
    private fun isBoundary(o: Any): Boolean {
        val n = o.javaClass.name
        return n.endsWith(".EndpointLoop") || n.endsWith(".EndpointCore") || n.endsWith(".LoopGroup") || n.startsWith("io.kuicksilver.testing.MemoryNetwork") ||
            o is kotlinx.coroutines.CoroutineDispatcher || n == "kotlinx.coroutines.ChildHandleNode" || n.endsWith("QuicEndpointImpl")
    }

    /** Objects every connection shares whatever path reaches them: classes, enums, Kotlin objects, interned strings, threads. */
    private fun isShared(o: Any): Boolean {
        val c = o.javaClass
        if (o is Class<*> || o is ClassLoader || o is Thread || c.isEnum || o is Enum<*>) return true
        if (o is String && o.intern() === o) return true
        return try { c.getDeclaredField("INSTANCE").let { Modifier.isStatic(it.modifiers) } } catch (_: NoSuchFieldException) { false } catch (_: SecurityException) { false }
    }

    /** Breadth-first over instance fields and array elements; [visit] returns false to stop descending through an object. */
    private fun walk(root: Any, visit: (String, Any, Int) -> Boolean) {
        val seen = IdentityHashMap<Any, Unit>()
        val queue = ArrayDeque<Pair<String, Any>>()
        queue += "" to root; seen[root] = Unit
        while (queue.isNotEmpty()) {
            val (path, o) = queue.removeFirst()
            if (!visit(path, o, 0)) continue
            val c = o.javaClass
            if (c.isArray) {
                if (c.componentType.isPrimitive) continue
                val a = o as Array<*>
                for (e in a) if (e != null && !seen.containsKey(e)) { seen[e] = Unit; queue += "$path[*]" to e }
                continue
            }
            var k: Class<*>? = c
            while (k != null) {
                for (f in k.declaredFields) {
                    if (Modifier.isStatic(f.modifiers) || f.type.isPrimitive) continue
                    val v = try { f.isAccessible = true; f.get(o) } catch (_: Exception) { null } ?: continue
                    if (seen.containsKey(v)) continue
                    seen[v] = Unit
                    queue += (if (path.isEmpty()) f.name else "$path.${f.name}") to v
                }
                k = k.superclass
            }
        }
    }

    private fun describe(o: Any): String {
        val c = o.javaClass
        return if (c.isArray) "${c.componentType.simpleName}[${java.lang.reflect.Array.getLength(o)}]" else c.name.substringAfterLast('.')
    }

    private fun shallow(o: Any): Long {
        val c = o.javaClass
        if (c.isArray) {
            val n = java.lang.reflect.Array.getLength(o).toLong()
            return align(16 + n * width(c.componentType))
        }
        var size = 12L
        var k: Class<*>? = c
        while (k != null) { for (f in k.declaredFields) if (!Modifier.isStatic(f.modifiers)) size += width(f.type); k = k.superclass }
        return align(size)
    }

    private fun width(t: Class<*>): Long = when (t) {
        java.lang.Long.TYPE, java.lang.Double.TYPE -> 8
        Integer.TYPE, java.lang.Float.TYPE -> 4
        java.lang.Short.TYPE, Character.TYPE -> 2
        java.lang.Byte.TYPE, java.lang.Boolean.TYPE -> 1
        else -> 4
    }

    private fun align(n: Long) = (n + 7) and 7L.inv()
}
