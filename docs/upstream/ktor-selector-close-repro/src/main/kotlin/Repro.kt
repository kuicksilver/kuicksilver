// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Reproducer for docs/upstream/ktor-selector-close.md. Usage: gradle run [--args=--control]
//
// A client socket whose SelectorManager has nothing else to do is closed while the peer is still sending. Expected: the
// descriptor is closed at once (the JVM's count of open descriptors drops) and the peer's next write fails. Actual with
// ktor-network on the JVM: the descriptor stays open; on Linux the peer then blocks in its write for good.
// --control adds a second client connection on the same SelectorManager that waits to read: the manager then keeps
// selecting, and the same close releases the descriptor at once.
import com.sun.management.UnixOperatingSystemMXBean
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.*
import kotlinx.coroutines.*
import java.lang.management.ManagementFactory
import java.util.concurrent.atomic.AtomicLong
import kotlin.system.exitProcess

private fun openDescriptors(): Long = (ManagementFactory.getOperatingSystemMXBean() as UnixOperatingSystemMXBean).openFileDescriptorCount

fun main(args: Array<String>) {
    val control = "--control" in args
    val ok = runBlocking { reproduce(control) }
    println(if (ok) "PASS" else "FAIL")
    exitProcess(if (ok) 0 else 1)
}

private suspend fun reproduce(control: Boolean): Boolean =
    coroutineScope {
        val serverSelector = SelectorManager(Dispatchers.IO)
        val clientSelector = SelectorManager(Dispatchers.IO) // the client's own manager: nothing else runs on it
        val listener = aSocket(serverSelector).tcp().bind("127.0.0.1", 0)
        val port = (listener.localAddress as InetSocketAddress).port
        val accepted = async { listener.accept() }
        val client = aSocket(clientSelector).tcp().connect("127.0.0.1", port)
        val server = accepted.await()
        if (control) {
            val otherAccepted = async { listener.accept() }
            val other = aSocket(clientSelector).tcp().connect("127.0.0.1", port)
            otherAccepted.await()
            launch { runCatching { other.openReadChannel().awaitContent() } } // a read interest that stays pending
        }
        client.openReadChannel() // the socket reads into this channel; the application never does

        val out = server.openWriteChannel()
        val written = AtomicLong()
        val writer =
            launch(Dispatchers.IO) {
                try {
                    val chunk = ByteArray(64 * 1024)
                    while (true) {
                        out.writeFully(chunk, 0, chunk.size)
                        out.flush()
                        written.addAndGet(chunk.size.toLong())
                    }
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e // cancelled below: the write was still blocked
                } catch (e: Throwable) {
                    println("server: write failed: $e")
                }
            }
        // Once the client's channel (1 MiB in Ktor 3) and both kernel buffers are full, the server's writes stop and the
        // client's reader waits for room in its channel: the client's manager has no interest pending.
        var last = -1L
        while (written.get() != last) {
            last = written.get()
            delay(500)
        }
        println("server: wrote $last bytes, then stalled")

        val before = openDescriptors()
        println("client: close() (open descriptors: $before)")
        client.close()
        val released = withTimeoutOrNull(5_000) { while (openDescriptors() >= before) delay(50) } != null
        println("client: descriptor released within 5 s: $released (open descriptors: ${openDescriptors()})")
        val writeEnded = withTimeoutOrNull(5_000) { writer.join() } != null
        println("server: write ended within 5 s: $writeEnded")

        writer.cancel()
        server.close()
        listener.close()
        clientSelector.close()
        serverSelector.close()
        released
    }
