// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** "Why QUIC": measured numbers behind the Lossy network screen, reproducible with tools/bench/why-quic.sh. */
const val WHY_QUIC_URL: String = "https://github.com/kuicksilver/kuicksilver/blob/main/docs/why-quic.md"

private const val MIB: Long = 1L shl 20

/** The demo's UI, the same on Android and iOS. */
@Composable
fun App(app: DemoApp) {
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.safeDrawingPadding().padding(12.dp)) {
                ServerField(app)
                var tab by remember { mutableIntStateOf(0) }
                PrimaryTabRow(selectedTabIndex = tab) {
                    listOf("Migration", "Lossy network", "Diagnostics").forEachIndexed { i, title ->
                        Tab(selected = tab == i, onClick = { tab = i }, text = { Text(title) })
                    }
                }
                Spacer(Modifier.height(8.dp))
                when (tab) {
                    0 -> MigrationScreen(app)
                    1 -> LossyScreen(app)
                    else -> DiagnosticsScreen(app)
                }
            }
        }
    }
}

@Composable
private fun ServerField(app: DemoApp) {
    val server by app.server.collectAsState()
    var host by remember { mutableStateOf(server.host) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            label = { Text("Demo server host (ports ${server.httpsPort} and ${server.httpPort})") },
            singleLine = true,
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(8.dp))
        OutlinedButton(onClick = { app.setHost(host) }, enabled = host.isNotBlank() && host.trim() != server.host) { Text("Use") }
    }
}

@Composable
private fun Choice(
    options: List<Pair<String, Long>>,
    selected: Long,
    onSelect: (Long) -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        for ((label, value) in options) FilterChip(selected = value == selected, onClick = { onSelect(value) }, label = { Text(label) })
    }
}

@Composable
private fun MigrationScreen(app: DemoApp) {
    val s by app.migration.state.collectAsState()
    var size by remember { mutableStateOf(50 * MIB) }
    var rate by remember { mutableStateOf(4 * MIB) }
    var resumeTcp by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        Text(
            "Start the downloads, then switch the network (turn Wi-Fi off). The HTTP/3 connection moves to the new network; " +
                "a TCP connection is tied to the old one. ${app.platform.referenceNote}",
            style = MaterialTheme.typography.bodySmall,
        )
        Text("Network: ${s.network}", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(vertical = 4.dp))
        Choice(listOf("20 MiB" to 20 * MIB, "50 MiB" to 50 * MIB), size) { size = it }
        Choice(listOf("2 MiB/s" to 2 * MIB, "4 MiB/s" to 4 * MIB, "unpaced" to 0L), rate) { rate = it }
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { resumeTcp = !resumeTcp }) {
            Checkbox(checked = resumeTcp, onCheckedChange = { resumeTcp = it })
            Text("Resume TCP with Range after a break (the cost of the workaround)", style = MaterialTheme.typography.bodySmall)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { app.migration.start("/bytes/$size" + if (rate > 0) "?rate=$rate" else "", resumeTcp) }, enabled = !s.running) {
                Text("Download ${size / MIB} MiB")
            }
            OutlinedButton(onClick = { app.migration.stop() }, enabled = s.running) { Text("Stop") }
        }
        for (lane in s.lanes) LaneCard(lane)
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
            items(s.events.asReversed()) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
        }
    }
}

@Composable
private fun LaneCard(lane: LaneState) {
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(8.dp)) {
            Text("${lane.name}: ${lane.status}", style = MaterialTheme.typography.titleSmall)
            Text(lane.note, style = MaterialTheme.typography.bodySmall)
            val total = lane.total
            if (total != null && total > 0) {
                LinearProgressIndicator(progress = { lane.received.toFloat() / total }, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp))
            }
            Text(
                "${mib(lane.received)} of ${total?.let(::mib) ?: "?"} MiB" + if (lane.detail.isNotEmpty()) " | ${lane.detail}" else "",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun LossyScreen(app: DemoApp) {
    val s by app.lossy.state.collectAsState()
    val server by app.server.collectAsState()
    var size by remember { mutableStateOf(MIB) }
    val uri = LocalUriHandler.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Text(
            "Lab mode: the phone does not lose packets, the server does. Run it behind tc netem on a machine with Docker " +
                "(samples/compose-demo/server/netem.sh 50 1: +50 ms round trip, 1 % of the server's packets lost) and point " +
                "the host above at that machine (now ${server.host}). Each engine downloads in turn over a warm connection, " +
                "20 times; the order flips every run.",
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "Why QUIC: measured numbers, reproducible (docs/why-quic.md)",
            color = MaterialTheme.colorScheme.primary,
            textDecoration = TextDecoration.Underline,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(vertical = 4.dp).clickable { uri.openUri(WHY_QUIC_URL) },
        )
        Choice(listOf("1 MiB" to MIB, "10 MiB" to 10 * MIB), size) { size = it }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { app.lossy.start(size, runs = 20) }, enabled = !s.running) { Text("Run 20 × ${size / MIB} MiB") }
            OutlinedButton(onClick = { app.lossy.stop() }, enabled = s.running) { Text("Stop") }
        }
        Text(s.progress, style = MaterialTheme.typography.bodySmall)
        for (row in s.rows) {
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Column(Modifier.padding(8.dp)) {
                    Text(row.name, style = MaterialTheme.typography.titleSmall)
                    Text(row.note, style = MaterialTheme.typography.bodySmall)
                    Text("download: ${stats(row.download)}", fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                    Text("time to response head: ${stats(row.head)}", fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                    if (row.failures > 0) Text("failed: ${row.failures}", fontSize = 12.sp)
                    if (row.notHttp3 > 0) Text("not over HTTP/3, left out: ${row.notHttp3}", fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
private fun DiagnosticsScreen(app: DemoApp) {
    val s by app.diagnostics.state.collectAsState()
    val server by app.server.collectAsState()
    var url by remember(server) { mutableStateOf(server.https("/")) }
    var demoCa by remember { mutableStateOf(true) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Text(
            "Any URL with Kuicksilver in Auto discovery: HTTP/1.1 first, HTTP/3 once the origin has announced it with Alt-Svc " +
                "(run it twice). The switch is the engine's http3Allowed kill switch, read on every request.",
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text("URL") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = s.http3Allowed, onCheckedChange = { app.diagnostics.setHttp3Allowed(it) })
            Spacer(Modifier.width(8.dp))
            Text("http3Allowed")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = demoCa, onCheckedChange = { demoCa = it })
            Spacer(Modifier.width(8.dp))
            Text(if (demoCa) "Trust: the demo CA (the demo server)" else "Trust: the system (public sites)")
        }
        Button(onClick = { app.diagnostics.run(url, demoCa) }, enabled = !s.running) { Text("GET") }
        for (line in s.lines) Text(line, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
}

private fun mib(bytes: Long): String {
    val tenths = bytes * 10 / MIB
    return "${tenths / 10}.${tenths % 10}"
}

private fun stats(s: SeriesStats?): String = if (s == null) "-" else "median ${s.median.toLong()} ms, p90 ${s.p90.toLong()} ms (n=${s.n})"
