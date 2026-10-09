// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.util.date.getTimeMillis
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readLine
import kotlinx.io.writeString

/**
 * An [AltSvcStore] kept in one text file (alternatives survive a restart, so the first request after a cold
 * start can already use HTTP/3). One record per line, tab-separated: origin, protocol, host (empty when the origin's),
 * port, expiry in epoch milliseconds, `1` when `persist=1`. The file is read once at construction (expired and
 * malformed records are dropped) and rewritten after every change through a temporary file and an atomic move, so a
 * crash leaves either the old or the new content. Calls are serialized by the engine's lock; two engines sharing one
 * file would overwrite each other's changes.
 *
 * @param path the store file; it need not exist yet, and an unreadable file starts an empty store.
 * @param clock the current time in epoch milliseconds, used to drop expired records on load.
 */
public class FileAltSvcStore(
    private val path: Path,
    private val clock: () -> Long = { getTimeMillis() },
) : AltSvcStore {
    private val map = HashMap<String, List<AltSvcEntry>>()

    init {
        load()
    }

    override fun get(origin: String): List<AltSvcEntry> = map[origin].orEmpty()

    override fun put(
        origin: String,
        entries: List<AltSvcEntry>,
    ) {
        if (entries.isEmpty()) {
            map.remove(origin)
        } else {
            map[origin] =
                entries.toList()
        }
        save()
    }

    override fun remove(origin: String) {
        if (map.remove(origin) != null) save()
    }

    override fun clearNonPersistent() {
        var changed = false
        for (k in map.keys.toList()) {
            val all = map[k]!!
            val kept = all.filter { it.persist }
            if (kept.size !=
                all.size
            ) {
                changed = true
                if (kept.isEmpty()) map.remove(k) else map[k] = kept
            }
        }
        if (changed) save()
    }

    private fun load() {
        if (!SystemFileSystem.exists(path)) return
        val now = clock()
        val lines = ArrayList<String>()
        try {
            SystemFileSystem.source(path).buffered().use { src ->
                while (true) {
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
            map[f[0]] = map[f[0]].orEmpty() + e
        }
    }

    private fun save() {
        val tmp = Path(path.parent ?: Path("."), path.name + ".tmp")
        try {
            SystemFileSystem.sink(tmp).buffered().use { sink ->
                for ((origin, entries) in map) {
                    for (e in entries) {
                        sink.writeString(
                            "$origin\t${e.protocol}\t${e.host ?: ""}\t${e.port}\t${e.expiresAtEpochMillis}\t${if (e.persist) 1 else 0}\n",
                        )
                    }
                }
            }
            SystemFileSystem.atomicMove(tmp, path)
        } catch (_: Exception) {
            runCatching { SystemFileSystem.delete(tmp, mustExist = false) }
        } // a store that cannot be written keeps working in memory
    }
}
