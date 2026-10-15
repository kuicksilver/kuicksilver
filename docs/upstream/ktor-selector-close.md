<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Draft: Ktor issue "JVM: a socket closed while its ActorSelectorManager is idle is never released"

Status: **draft, not filed**. Filing it is the owner's decision. Target: YouTrack, project KTOR, subsystem `Network`
(ktor-network). Checked against the ktor-network 3.6.0 sources only (`ActorSelectorManager`, `SelectorManagerSupport`,
`SocketBase`, `NIOSocketImpl`); `main` and the issue tracker were not checked for an existing report.

Kuicksilver works around it in its own code (see "Workaround in Kuicksilver" at the end); the text below is what would go
upstream.

---

**Title:** JVM: `Socket.close()` does not close the descriptor while the `ActorSelectorManager` has no pending interest

**Affected:** ktor-network 3.6.0 on the JVM (and Android, which uses the JVM artifact). Every user of `aSocket(selector)`
with the default `SelectorManager()`, so presumably the CIO client and server engines too (same code path, not tested
separately). Kotlin/Native is not affected: `NativeSocketImpl.actualClose` shuts the descriptor down itself and asks the
selector to close it with a `CLOSE` interest.

**Summary.** `NIOSocketImpl.actualClose()` calls `SocketChannel.close()` and then `selector.notifyClosed(this)`. NIO does
not close the descriptor of a channel that is still registered with a selector: it only marks it closing (and shuts
down its output, sending a FIN) and closes the descriptor when the selector deregisters the key, which happens at the
start of the next `select`. `ActorSelectorManager.notifyClosed` cancels the key and calls `selectWakeup()`, which wakes
the selector only when it is inside `select` (`inSelect`). When the manager has no pending interest (`pending == 0`, for
example because the last `select` selected every registered key), its loop does not select at all: it suspends in
`receiveOrNull()` waiting for a new interest. The cancelled key then stays registered and the descriptor stays open
until some other socket of the same manager publishes an interest, possibly never.

**Consequences.** The connection is half closed: our side sent a FIN but still holds the descriptor, with whatever the
peer sent still unread in its receive buffer. On Linux the receive window stays at zero, so a peer that is writing (a
server streaming a response the client abandoned) blocks forever in CLOSE_WAIT instead of getting a reset; the
descriptor and its buffers leak until the manager does something else or is closed. On macOS the reproducer below passes
(the peer's write fails anyway); whether the descriptor stays open there was not investigated.

**Reproducer** (JVM, Linux; deterministic):

1. Create a `SelectorManager(Dispatchers.Default)` used by one client socket only, and a separate one for the server.
2. Connect, call `openReadChannel()` on the client and never read from the channel. On the server, write 64 KiB chunks
   in a loop.
3. Wait until the server's writes stop making progress: the client's channel (1 MiB) and both kernel buffers are full,
   the client's reader coroutine waits for room in its channel, and the last `select` selected the only key, so
   `pending == 0`.
4. `client.close()`.

Expected: the server's write fails within milliseconds (the client's descriptor is closed with unread data, so its
kernel resets the connection). Actual: the server's write blocks indefinitely; `/proc/net/tcp` shows the client socket
in FIN_WAIT2 with unread data and the server socket in CLOSE_WAIT with megabytes queued and the zero-window probe timer
running. Closing the client's `SelectorManager` releases both.

**Suggested fix.** In `ActorSelectorManager.notifyClosed`, after cancelling the key, make sure a `selectNow()` runs even
when the loop is idle: for example count the cancellation (`cancelled++` is already handled by the `cancelled > 0`
branch of `process`) and resume the mailbox wait (`continuation.resume(Unit)`), or enqueue a marker into
`selectionQueue` so the loop runs once and its `selectNow()` deregisters the key.

---

## Workaround in Kuicksilver

`engineSelector()` (`kuicksilver-ktor-network`, `EngineSelector.kt`) is the `SelectorManager` both engines use (the client
engine's and every server listener's). On the JVM and Android it registers the read end of a pipe nobody writes to and
waits on it for the manager's lifetime, so the manager always has one interest pending and keeps selecting (with its
500 ms timeout, and woken at once by `notifyClosed` since it is then inside `select`); every select deregisters the
cancelled keys, which is when NIO closes their descriptors. Cost: one pipe (two descriptors) per manager and a select
every 500 ms while idle. On Kotlin/Native it does nothing. Regression test: `EngineSelectorTest` (fails on Linux without
the pipe, 3 runs of 3); found by `AbandonedBodyTest.abandonedBodyEndsServerHandlerH1`, which failed in about 2 of 5 runs
in the linux-x64 Docker JVM step. Remove the workaround once a fixed Ktor release is the supported version
(`KtorVersionPolicy.SUPPORTED`) and `EngineSelectorTest` passes with a plain `SelectorManager`.
