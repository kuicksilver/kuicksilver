// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.util.date.getTimeMillis
import io.ktor.util.logging.KtorSimpleLogger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.writeString
import kotlin.random.Random

/**
 * An [AltSvcStore] kept in one text file (alternatives survive a restart, so the first request after a cold
 * start can already use HTTP/3). One record per line, tab-separated: origin, protocol, host (empty when the origin's),
 * port, expiry in epoch milliseconds, `1` when `persist=1`. The file is read once at construction: it is input like a
 * header, so every field is checked again (the origin's `https://host:port` form, the protocol token, the host as the
 * `Alt-Svc` parser takes it, the ports, the expiry, the persist flag) and a record failing a check is dropped, as is an
 * expired one; at most 1000 origins of 8 alternatives are kept, and of a file over 8 MiB only the records in its first
 * 8 MiB are read (a full store takes less than that). The
 * engine also checks each entry it uses as it checks a header's. The file is rewritten after every change
 * through a uniquely named temporary file and an atomic move, so a crash leaves either the old or the new content
 * (on Android API 24-25, which lacks `java.nio.file`, the move is a `java.io.File.renameTo`, atomic on one filesystem).
 * A store that cannot be written keeps working in memory; the first failed write is logged as a warning.
 * A repeated header always replaces the alternatives in memory (RFC 7838 section 3); it is not
 * written when it only moves the expiry later by less than half the new lifetime. The store keeps at
 * most 1000 origins, dropping the least recently used (threat-model 3.18). Used by the engine, the file is written
 * after the engine's lock is released. Calls are serialized by the engine's lock; two engines sharing one file would
 * overwrite each other's changes.
 *
 * @param path the store file; it need not exist yet, and an unreadable file starts an empty store.
 * @param clock the current time in epoch milliseconds, used to drop expired records on load.
 */
@OptIn(ExperimentalKuicksilverApi::class)
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
    private var warned = false

    /** The atomic replace of the store file; a test seam for the platforms where kotlinx-io cannot do it. */
    internal var atomicMove: (Path, Path) -> Unit = { source, destination -> SystemFileSystem.atomicMove(source, destination) }

    /** Where the first failed write is reported. */
    internal var warn: (String) -> Unit = { LOG.warn(it) }

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

    /**
     * Kept in the file as its first line (`network`, a tab, the id's UTF-8 bytes in hex); a file without that line, or with a
     * damaged one, has none.
     */
    @ExperimentalKuicksilverApi
    override var networkId: String? = null
        set(value) {
            if (field == value) return
            field = value
            if (map.isNotEmpty() || persisted.isNotEmpty()) changed()
        }

    @ExperimentalKuicksilverApi
    override fun clear() {
        if (map.isEmpty() && persisted.isEmpty()) return
        map.clear()
        changed()
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
                networkId?.let { append("$NETWORK_RECORD\t${it.encodeToByteArray().toHexString()}\n") }
                for ((origin, entries) in map) {
                    for (e in entries) {
                        append(
                            "$origin\t${e.protocol}\t${e.host ?: ""}\t${e.port}\t${e.expiresAtEpochMillis}\t${if (e.persist) 1 else 0}\n",
                        )
                    }
                }
            }
        val write = { write(seq, text) }
        if (deferWrites) pending = write else write()
    }

    private fun load() {
        if (!SystemFileSystem.exists(path)) return
        val now = clock()
        val maxLines = AltSvcCache.MAX_ORIGINS * AltSvcCache.MAX_ENTRIES_PER_ORIGIN
        val lines =
            try {
                SystemFileSystem.source(path).buffered().use { src ->
                    // at most MAX_FILE_BYTES, which a full store (8000 records of bounded fields) never reaches: the records
                    // of a longer file up to that point are read, the rest (and the line cut by the limit) is not
                    val buf = ByteArray(MAX_FILE_BYTES)
                    var n = 0
                    while (n < buf.size) {
                        val r = src.readAtMostTo(buf, n, buf.size)
                        if (r < 0) break
                        n += r
                    }
                    val cut = n == buf.size && !src.exhausted()
                    val all = buf.decodeToString(0, n).split('\n')
                    (if (cut) all.dropLast(1) else all).take(maxLines).map { it.removeSuffix("\r") }
                }
            } catch (_: Exception) {
                return
            } // an unreadable file is an empty store
        lines.firstOrNull()?.let { first ->
            val f = first.split('\t')
            if (f.size == 2 && f[0] == NETWORK_RECORD) networkId = networkOf(f[1])
        }
        for (line in lines) {
            val (origin, e) = recordOf(line) ?: continue
            if (e.expiresAtEpochMillis <= now) continue
            val had = map.remove(origin).orEmpty()
            map[origin] = if (had.size < AltSvcCache.MAX_ENTRIES_PER_ORIGIN) had + e else had
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
            try {
                atomicMove(tmp, path)
            } catch (_: UnsupportedOperationException) {
                renameReplacing(tmp, path) // kotlinx-io's JVM atomicMove needs java.nio.file: Android API 26+
            }
        } catch (e: Exception) {
            runCatching { SystemFileSystem.delete(tmp, mustExist = false) }
            // a store that cannot be written keeps working in memory, but says so once
            if (!warned) {
                warned = true
                warn("Alt-Svc store $path cannot be written, alternatives are kept in memory only: $e")
            }
        }
    }

    internal companion object {
        private val LOG = KtorSimpleLogger("io.kuicksilver.ktor.client.FileAltSvcStore")

        /**
         * The origin and entry of one store record, or null when any field is not what the engine writes. The file is input
         * like a header (threat-model 3.14, 3.18): written by an older version, edited by hand or by another program, it
         * must not bring in what the `Alt-Svc` parser refuses. The origin is `https://host:port` (the engine's key,
         * [originKeyOf]); the protocol an RFC 9110 token; the alternative's host empty (the origin's) or a connection
         * target, an IPv6 address without its brackets; ports digits in 1..65535; the expiry digits; persist `0` or `1`.
         * Where the engine may use an entry (the privileged-port and destination rules) is checked when it does
         * ([AltSvcCache.h3For]), for every store.
         */
        internal fun recordOf(line: String): Pair<String, AltSvcEntry>? {
            val f = line.split('\t')
            if (f.size != 6) return null
            // bounded fields (a DNS name has at most 253 characters, an ALPN id 255 bytes) keep a full store within the cap
            if (f[0].length > 8 + MAX_FIELD + 6 || f[1].length > MAX_FIELD || f[2].length > MAX_FIELD) return null
            val origin = f[0]
            if (!origin.startsWith("https://")) return null
            val authority = origin.removePrefix("https://")
            val colon = authority.lastIndexOf(':')
            if (colon <= 0) return null
            AltSvcParser.portOf(authority.substring(colon + 1)) ?: return null
            if (!AltSvcParser.isAltHost(authority.substring(0, colon), bracketed = true)) return null
            val protocol = f[1]
            if (protocol.isEmpty() || !protocol.all { it.isTchar() }) return null
            val host = f[2]
            if (host.isNotEmpty() && !AltSvcParser.isAltHost(host, bracketed = false)) return null
            val port = AltSvcParser.portOf(f[3]) ?: return null
            if (f[4].isEmpty() || f[4].length > 19 || f[4].any { it !in '0'..'9' }) return null
            val expires = f[4].toLongOrNull() ?: return null
            val persist =
                when (f[5]) {
                    "1" -> true
                    "0" -> false
                    else -> return null
                }
            return origin to AltSvcEntry(protocol, host.ifEmpty { null }, port, expires, persist)
        }

        /** RFC 9110 section 5.6.2 `tchar`. */
        private fun Char.isTchar(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9' || this in "!#$%&'*+-.^_`|~"

        /** The first field of the line that keeps [networkId]: no origin, so a version that does not know it skips it. */
        private const val NETWORK_RECORD = "network"

        /** The network id of its hex form, or null when [hex] is not one (lowercase digits, whole bytes, valid UTF-8). */
        private fun networkOf(hex: String): String? {
            if (hex.length % 2 != 0 || hex.any { it !in '0'..'9' && it !in 'a'..'f' }) return null
            return runCatching { hex.hexToByteArray().decodeToString(throwOnInvalidSequence = true) }.getOrNull()
        }

        /**
         * The longest protocol id and host a record may have: RFC 7301 section 3.1, `opaque ProtocolName<1..2^8-1>`; RFC 1035
         * section 2.3.4, "names 255 octets or less" (the dotted text form of such a name is shorter).
         */
        private const val MAX_FIELD = 255

        /** The most of a store file that is read: twice what 8000 records of bounded fields can take. */
        internal const val MAX_FILE_BYTES: Int = 8 shl 20
    }
}

/**
 * Renames [source] to [destination], replacing it, where `SystemFileSystem.atomicMove` is unsupported; throws when it
 * cannot.
 */
internal expect fun renameReplacing(
    source: Path,
    destination: Path,
)
