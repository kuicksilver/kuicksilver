// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.util.date.getTimeMillis
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readLine
import kotlinx.io.writeString
import kotlin.random.Random

/**
 * An [AltSvcStore] kept in one text file (alternatives survive a restart, so the first request after a cold
 * start can already use HTTP/3). One record per line, tab-separated: origin, protocol, host (empty when the origin's),
 * port, expiry in epoch milliseconds, `1` when `persist=1`. The file is read once at construction (expired and
 * malformed records are dropped, at most 1000 origins of 8 alternatives are kept) and rewritten after every change
 * through a uniquely named temporary file and an atomic move, so a crash leaves either the old or the new content.
 * A repeated header always replaces the alternatives in memory (RFC 7838 section 3); it is not
 * written when it only moves the expiry later by less than half the new lifetime. The store keeps at
 * most 1000 origins, dropping the least recently used (threat-model 3.18). Used by the engine, the file is written
 * after the engine's lock is released. Calls are serialized by the engine's lock; two engines sharing one file would
 * overwrite each other's changes.
 *
 * @param path the store file; it need not exist yet, and an unreadable file starts an empty store.
 * @param clock the current time in epoch milliseconds, used to drop expired records on load.
 */
public class FileAltSvcStore(
    private val path: Path,
    private val clock: () -> Long = { getTimeMillis() },
) : AltSvcStore {
    private val map = LinkedHashMap<String, List<AltSvcEntry>>()

    /** Set by [AltSvcCache]: changes leave a [takePendingWrite] for the engine to run after its lock. */
    internal var deferWrites = false

    private var pending: (() -> Unit)? = null

    /** The content of the last snapshot: what is (or is about to be) on disk. */
    private var persisted: Map<String, List<AltSvcEntry>> = emptyMap()
    private var snapshots = 0L
    private var written = -1L

    init {
        load()
    }

    override fun get(origin: String): List<AltSvcEntry> = map.touch(origin).orEmpty()

    override fun put(
        origin: String,
        entries: List<AltSvcEntry>,
    ) {
        if (entries.isEmpty()) return remove(origin)
        val kept = entries.take(AltSvcCache.MAX_ENTRIES_PER_ORIGIN)
        map.touch(origin)
        val disk = persisted[origin]
        // a new header replaces the cached alternatives (RFC 7838 section 3); only the disk write may be skipped
        map[origin] = kept
        if (disk != null && disk == kept && kept.indices.all { fresh(disk[it], kept[it]) }) return
        map.evictEldest(AltSvcCache.MAX_ORIGINS)
        changed()
    }

    override fun remove(origin: String) {
        if (map.remove(origin) != null) changed()
    }

    override fun clearNonPersistent() {
        var changed = false
        for (k in map.keys.toList()) {
            val all = map[k]!!
            val kept = all.filter { it.persist }
            if (kept.size != all.size) {
                changed = true
                if (kept.isEmpty()) map.remove(k) else map[k] = kept
            }
        }
        if (changed) changed()
    }

    /**
     * The [old] entry on disk still stands for [new]: the expiry did not move earlier, and moved later by less than half of
     * [new]'s remaining lifetime.
     */
    private fun fresh(
        old: AltSvcEntry,
        new: AltSvcEntry,
    ): Boolean {
        val delta = new.expiresAtEpochMillis - old.expiresAtEpochMillis
        return delta >= 0 && delta < (new.expiresAtEpochMillis - clock()) / 2
    }

    internal fun takePendingWrite(): (() -> Unit)? = pending.also { pending = null }

    /** Snapshots the content now (under the caller's lock); the write itself runs now or, behind the engine, later. */
    private fun changed() {
        val seq = snapshots++
        persisted = LinkedHashMap(map)
        val text =
            buildString {
                for ((origin, entries) in map) {
                    for (e in entries) {
                        append("$origin\t${e.protocol}\t${e.host ?: ""}\t${e.port}\t${e.expiresAtEpochMillis}\t${if (e.persist) 1 else 0}\n")
                    }
                }
            }
        val write = { write(seq, text) }
        if (deferWrites) pending = write else write()
    }

    private fun load() {
        if (!SystemFileSystem.exists(path)) return
        val now = clock()
        val lines = ArrayList<String>()
        val maxLines = AltSvcCache.MAX_ORIGINS * AltSvcCache.MAX_ENTRIES_PER_ORIGIN
        try {
            SystemFileSystem.source(path).buffered().use { src ->
                while (lines.size < maxLines) {
                    lines += src.readLine() ?: break
                }
            }
        } catch (_: Exception) {
            return
        } // an unreadable file is an empty store
        for (line in lines) {
            val f = line.split('\t')
            if (f.size != 6 || f[0].isEmpty() || f[1].isEmpty()) continue
            val port = f[3].toIntOrNull()?.takeIf { it in 1..65_535 } ?: continue
            val expires = f[4].toLongOrNull() ?: continue
            if (expires <= now) continue
            val e = AltSvcEntry(f[1], f[2].ifEmpty { null }, port, expires, f[5] == "1")
            val had = map.remove(f[0]).orEmpty()
            map[f[0]] = if (had.size < AltSvcCache.MAX_ENTRIES_PER_ORIGIN) had + e else had
        }
        map.evictEldest(AltSvcCache.MAX_ORIGINS)
        persisted = LinkedHashMap(map)
    }

    /** Writes snapshot [seq] unless a newer one is already on disk; the engine runs these one at a time. */
    private fun write(
        seq: Long,
        text: String,
    ) {
        if (seq <= written) return
        written = seq
        val tmp = Path(path.parent ?: Path("."), "${path.name}.${Random.nextLong().toULong()}.tmp")
        try {
            SystemFileSystem.sink(tmp).buffered().use { it.writeString(text) }
            SystemFileSystem.atomicMove(tmp, path)
        } catch (_: Exception) {
            runCatching { SystemFileSystem.delete(tmp, mustExist = false) }
        } // a store that cannot be written keeps working in memory
    }
}
