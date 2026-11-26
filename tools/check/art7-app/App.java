// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package app;

import io.kuicksilver.ktor.client.KuicksilverEngineConfig;
import io.kuicksilver.ktor.client.KuicksilverEventListener;
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine;
import io.kuicksilver.ktor.server.KuicksilverServerEventListener;
import io.kuicksilver.quic.KuicksilverLogger;
import io.kuicksilver.quic.LogLevel;
import io.kuicksilver.quic.QlogSink;
import io.kuicksilver.quic.QlogTrace;
import io.kuicksilver.quic.qlog.AsyncQlogSink;
import io.kuicksilver.tls.TlsRole;
import kotlinx.coroutines.Dispatchers;

/**
 * The app of tools/check/art7-loops.sh, shrunk with the AARs by R8 as an application's release build would be: it installs
 * an event listener, a logger and an AsyncQlogSink on the client's and the server's configuration, so that R8 keeps the
 * code that calls them (without one, R8 proves the listener null and removes its calls, and the check would see none),
 * two classes of each listener and logger, so that R8 keeps their calls virtual as an app with several engines has them.
 */
public final class App {
    static int events;

    // two of each, so that R8 cannot devirtualize the calls to the one class it would otherwise see
    static final class Logger implements KuicksilverLogger {
        @Override public boolean isEnabled(LogLevel level) { return true; }
        @Override public void log(LogLevel level, String message, Throwable cause) { events++; }
    }

    static final class QuietLogger implements KuicksilverLogger {
        @Override public boolean isEnabled(LogLevel level) { return level == LogLevel.Warn; }
        @Override public void log(LogLevel level, String message, Throwable cause) { events--; }
    }

    static final class Listener extends KuicksilverEventListener { }

    static final class CountingListener extends KuicksilverEventListener {
        @Override public void retry(io.ktor.client.request.HttpRequestData request, int attempt, Throwable cause) { events++; }
    }

    static final class ServerListener extends KuicksilverServerEventListener { }

    static final class OtherServerListener extends KuicksilverServerEventListener { }

    static final class Sink implements QlogSink {
        @Override public QlogTrace open(String odcidHex, TlsRole role) {
            return new QlogTrace() {
                @Override public void write(String record) { events++; }
                @Override public void close() { events++; }
            };
        }
    }

    public static void client(KuicksilverEngineConfig config, boolean quiet) {
        config.getObservability().setEventListener(quiet ? new Listener() : new CountingListener());
        config.getObservability().setLogger(quiet ? new QuietLogger() : new Logger());
        config.getObservability().setQlog(new AsyncQlogSink(new Sink(), 8192, 1, Dispatchers.getIO()));
    }

    public static void server(KuicksilverApplicationEngine.Configuration config, boolean quiet) {
        config.getObservability().setEventListener(quiet ? new ServerListener() : new OtherServerListener());
        config.getObservability().setLogger(quiet ? new QuietLogger() : new Logger());
        config.getObservability().setQlog(new AsyncQlogSink(new Sink(), 8192, 1, Dispatchers.getIO()));
    }
}
