<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Draft: Ktor issue "JVM: a socket closed while its SelectorManager is idle keeps its file descriptor"

Status: **draft, not filed**. Filing it is the owner's decision. Where: [YouTrack, project KTOR](https://youtrack.jetbrains.com/newIssue?project=KTOR)
(Ktor's GitHub issues are disabled and point there), subsystem *Network* / *Sockets*. Ktor's
[CONTRIBUTING.md](https://github.com/ktorio/ktor/blob/main/CONTRIBUTING.md#reporting-issues) asks for: a search for
duplicates, a test against the latest release, the platform and OS, a complete minimal reproducer (a test is welcome),
expected versus actual behaviour. Its [AI policy](https://github.com/ktorio/ktor/blob/main/AI_POLICY.md) allows a
tool-assisted issue description if it is labelled as such (it strongly recommends writing it yourself) and asks that
comments in the discussion are not written with AI tools.

Duplicate search (2026-10-15, YouTrack KTOR, queries `ActorSelectorManager`, `notifyClosed`, `CLOSE_WAIT`, `FIN_WAIT2`,
`socket close file descriptor leak`, `selector close socket not closed`, `socket not closed cancelled key`): no report
of this. Related but different:
[KTOR-9741](https://youtrack.jetbrains.com/issue/KTOR-9741) (CIO server: request handler leak on a half-closed idle
connection after a response of 1 MB or more; fixed in 3.5.2 in `ServerPipeline`, not in the selector),
[KTOR-9683](https://youtrack.jetbrains.com/issue/KTOR-9683) (cancelling a `SelectorManager`'s job did not close it;
fixed), [KTOR-7255](https://youtrack.jetbrains.com/issue/KTOR-7255) (descriptor leak on Native; fixed).

Kuicksilver works around it in its own code (see "Workaround in Kuicksilver" at the end). Everything above the line
below is context for the owner; the text below the line is the proposed issue.

---

**Title:** JVM sockets: `Socket.close()` does not close the file descriptor while the `ActorSelectorManager` has no pending interest

**Summary.** On the JVM, closing a TCP socket whose `SelectorManager` has nothing else to wait for leaves the socket's
file descriptor open. NIO closes a channel that is registered with a selector only when that selector's next selection
operation deregisters the key; `ActorSelectorManager`, when no interest is pending, does not select at all but waits for a
new interest, and `notifyClosed()` cannot wake it from that wait. The descriptor stays open, half closed (the JDK shuts
its output down, so the peer gets a FIN), with whatever the peer sent still in its receive buffer, until another socket of
the same manager publishes an interest or the manager is closed. On Linux a peer that is still writing then blocks for
good: the receive window of the half-closed socket stays at zero, so the peer sits in `CLOSE_WAIT` with its data queued
and never gets the reset it would get from a closed socket.

**Environment.**
- ktor-network 2.3.13, 3.0.3, 3.6.0 and the EAP build 3.6.0-eap-1684 (published 2026-10-11), all affected; the code
  involved is unchanged on `main` (`4016bdfe`, 2026-10-12).
- JVM: Zulu 21.0.5 on macOS 26.7 (arm64), Temurin 21 on Linux (arm64, Docker). Android uses the same JVM artifact
  (not tested). Kotlin/Native is not affected: `NativeSocketImpl.actualClose` shuts the descriptor down and asks its
  selector to close it with a `CLOSE` interest.
- Engine: none, plain `aSocket(selector).tcp()`. The CIO client and server use the same `SelectorManager` and are
  presumably affected (not tested separately). Found with a Ktor HTTP/1.1 client engine whose response body the
  application left unread: the server's handler kept writing that body for good.

**Steps to reproduce.** A standalone Gradle project that depends on `ktor-network` only:
[ktor-selector-close-repro](ktor-selector-close-repro/README.md) (attach it to the issue as a zip; a single `Repro.kt`).
`gradle run -PktorVersion=3.6.0`:

1. A client socket on its own `SelectorManager(Dispatchers.IO)` connects to a server socket on a second manager.
2. The client calls `openReadChannel()` and never reads it; the server writes 64 KiB chunks in a loop.
3. Wait until the server's writes stop making progress: the client's channel and both kernel buffers are full, the
   client's reader coroutine waits for room in its channel, and the client's manager has no interest pending.
4. `client.close()`.

**Expected.** The client's descriptor is closed at once (the JVM's open-descriptor count drops by one), and the server's
next write fails with a reset or broken pipe.

**Actual.** The descriptor stays open; on Linux the server's write stays blocked. `/proc/net/tcp` shows the client
socket in `FIN_WAIT2` with unread data and the server socket in `CLOSE_WAIT` with megabytes queued and the zero-window
probe timer running. Closing the client's `SelectorManager` releases both. With a second connection on the same manager
that waits to read (`--args=--control`), the same `close()` releases the descriptor at once.

| Ktor | macOS (JVM) | Linux (JVM) | `--control` |
|---|---|---|---|
| 2.3.13 | descriptor kept (the server's write fails anyway) | descriptor kept, server write blocked | released |
| 3.0.3 | descriptor kept | descriptor kept, server write blocked | released |
| 3.6.0 | descriptor kept | descriptor kept, server write blocked | released |
| 3.6.0-eap-1684 | descriptor kept | descriptor kept, server write blocked | released |

**Root cause** (links at tag 3.6.0).

1. The client's reader coroutine reads, drops its `READ` interest and suspends in `channel.writeFully(buffer)` once the
   socket's `ByteChannel` is full
   ([CIOReader.kt#L53-L55](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/sockets/CIOReader.kt#L53-L55);
   the direct variant drops it at
   [#L84](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/sockets/CIOReader.kt#L84)).
   The key stays registered with interest `0`.
2. After a selection, `pending = keys.size - selectedCount` plus the selected keys that still have interest
   ([SelectorManagerSupport.kt#L58-L61](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/selector/SelectorManagerSupport.kt#L58-L61),
   [#L93](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/selector/SelectorManagerSupport.kt#L93)).
   When the last selection selected the only registered key, `pending == 0` and `cancelled == 0`.
3. With nothing pending, the manager's loop neither selects nor `selectNow()`s: it suspends in `mb.receiveOrNull()`
   until a new interest is published
   ([ActorSelectorManager.kt#L79-L107](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/selector/ActorSelectorManager.kt#L79-L107),
   the wait at [#L104](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/selector/ActorSelectorManager.kt#L104)).
4. `Socket.close()` ([SocketBase.kt#L38-L46](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/common/src/io/ktor/network/sockets/SocketBase.kt#L38-L46))
   ends with `NIOSocketImpl.actualClose()`, which calls `channel.close()` and then `selector.notifyClosed(this)`
   ([NIOSocketImpl.kt#L41-L50](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/sockets/NIOSocketImpl.kt#L41-L50)).
5. `channel.close()` of a non-blocking channel that is still registered does not close the descriptor: the JDK's
   `SocketChannelImpl` shuts the output down (`Net.shutdown(fd, SHUT_WR)`, the FIN the peer sees) and defers the close
   to `kill()`, which `SelectorImpl.processDeregisterQueue()` calls when a selection operation deregisters the cancelled
   key (`implCloseNonBlockingMode`, `tryClose`, `kill` in `sun.nio.ch.SocketChannelImpl`; `processDeregisterQueue` in
   `sun.nio.ch.SelectorImpl`, JDK 21).
6. `notifyClosed()` cancels the key and calls `selectWakeup()`
   ([ActorSelectorManager.kt#L142-L150](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/selector/ActorSelectorManager.kt#L142-L150)),
   which calls `Selector.wakeup()` only while the loop is inside `select` (`inSelect`,
   [#L129-L133](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/selector/ActorSelectorManager.kt#L129-L133),
   [#L109-L120](https://github.com/ktorio/ktor/blob/3.6.0/ktor-network/jvm/src/io/ktor/network/selector/ActorSelectorManager.kt#L109-L120)).
   The loop is in the mailbox wait instead, nothing is published to the mailbox, `cancelled` is not incremented, so no
   selection operation runs and the cancelled key is never deregistered.

**History.** Not a regression. `process()`, `select()`, `selectWakeup()` and `notifyClosed()` are identical in 2.3.13,
every 3.x release up to 3.6.0 and `main`, and differ from 1.6.8 only in formatting. The mailbox wait for the idle case is part of the original
`ActorSelectorManager` design (its MPSC-queue form is from
[965c0a317](https://github.com/ktorio/ktor/commit/965c0a317), March 2018, in 0.9.2); the `cancelled > 0` branch that
does run `selectNow()` for keys `handleSelectedKey` cancelled was refined in
[532d5804f](https://github.com/ktorio/ktor/commit/532d5804f) (December 2019, 1.3.0), but keys cancelled by
`notifyClosed()` never reach that counter.

**Impact.** Every JVM user of ktor-network sockets whose `SelectorManager` can go idle: a descriptor (and its kernel
buffers) per closed socket, until some other socket of the manager does something; for a long-idle client or a quiet
server listener that can be indefinitely. On Linux the peer is also held: it cannot learn that the connection is gone
while it is sending, so a server streaming a response to a client that gave up keeps its handler, buffers and
connection. Low traffic makes it worse, not better: a busy manager selects all the time and flushes the cancelled keys
as a side effect.

**Suggested fix** (a sketch, not tested against Ktor's test suite). Make a close reach the selection loop even when it
is idle, so that a `selectNow()` deregisters the cancelled key:

```kotlin
// ActorSelectorManager
override fun notifyClosed(selectable: Selectable) {
    cancelAllSuspensions(selectable, ClosedChannelException())
    selectorRef?.let { selector ->
        selectable.channel.keyFor(selector)?.let { key ->
            key.cancel()
            closedKeys.incrementAndGet() // new AtomicInteger: keys cancelled from outside the loop
            selectWakeup()               // as today: wakes a loop that is inside select()
            wakeMailbox()                // new: resume a loop that waits in receiveOrNull()
        }
    }
}

// in process(): treat keys cancelled by notifyClosed like the ones handleSelectedKey cancelled
if (cancelled > 0 || closedKeys.getAndSet(0) > 0) {
    selector.selectNow() // processDeregisterQueue: the JDK closes the descriptors now
    ...
}
```

where `wakeMailbox()` resumes `receiveOrNullSuspend()` so that it returns to the loop (for example by returning a
sentinel, or by letting `receiveOrNull()` return early when `closedKeys > 0`). An alternative that is simpler but costs
idle wake-ups: wait in the mailbox with a timeout and `selectNow()` after it. A regression test: the reproducer above as
a JVM test (client on its own manager, peer writing, client channel full, `close()`, then assert that the peer's write
fails or that the descriptor count drops within a second).

**Workaround for users.** Keep one interest pending on the manager for its whole life, so that it always selects: for
example register the read end of a `Pipe` that nobody writes to as a `Selectable` and `select(it, READ)` on it once.
Closing the `SelectorManager` also releases everything.

---

## Workaround in Kuicksilver

`engineSelector()` (`kuicksilver-ktor-network`, `EngineSelector.kt`) is the `SelectorManager` of both engines (the client
engine's and every server listener's). On the JVM and Android it registers the read end of a pipe nobody writes to and
waits on it for the manager's lifetime, so the manager always has an interest pending and keeps selecting (500 ms
timeout, woken at once by `notifyClosed` since it is then inside `select`); every select deregisters the cancelled keys,
which is when the JDK closes their descriptors. Cost: one pipe (two descriptors) per manager and a select every 500 ms
while idle. On Kotlin/Native it does nothing. Regression test: `EngineSelectorTest` (on Linux it fails in 3 runs of 3
without the pipe); found by `AbandonedBodyTest.abandonedBodyEndsServerHandlerH1`, which failed in about 2 of 5 runs of
the linux-x64 Docker JVM step and passed 12 of 12 with the workaround. Remove it once a fixed Ktor release is the
supported version (`KtorVersionPolicy.SUPPORTED`) and `EngineSelectorTest` passes with a plain `SelectorManager`.
