package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.ResourceLock;

import space.seclume.secret.CallbackSecretProvider;

/**
 * A server that ignores the cancellation and trickles a byte now and then:
 * the network timeout counts only silence and never fires. The query timeout
 * cancels, the grace runs out, and the connection is closed - within the
 * timeout and the grace, not whenever the server is done.
 */
@Timeout(60)
@ResourceLock("seclume.queryTimeoutGraceSeconds")
class QueryKillTest {

    /** A PostgreSQL that lets anybody in, then answers the first query a byte at a time. */
    static final class TricklingPostgres implements AutoCloseable {
        final ServerSocket listener;
        final AtomicInteger cancels = new AtomicInteger();
        final AtomicBoolean stop = new AtomicBoolean();
        final Thread thread;
        /** Answers no query at all: not a byte - the silence a network timeout would see. */
        final boolean silent;

        TricklingPostgres() throws IOException {
            this(false);
        }

        TricklingPostgres(boolean silent) throws IOException {
            this.silent = silent;
            listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            thread = new Thread(this::serve, "trickling-postgres");
            thread.setDaemon(true);
            thread.start();
        }

        private void serve() {
            while (!stop.get()) {
                Socket socket;
                try {
                    socket = listener.accept();
                } catch (IOException closed) {
                    return;
                }
                Thread one = new Thread(() -> session(socket));
                one.setDaemon(true);
                one.start();
            }
        }

        private void session(Socket socket) {
            try (socket; DataInputStream in = new DataInputStream(socket.getInputStream())) {
                OutputStream out = socket.getOutputStream();
                int length = in.readInt();
                int code = in.readInt();
                if (code == 80877102) {                       // CancelRequest: taken, ignored
                    in.readNBytes(length - 8);
                    cancels.incrementAndGet();
                    return;
                }
                if (code == 80877103) {                       // SSLRequest: no
                    out.write('N');
                    out.flush();
                    length = in.readInt();
                    code = in.readInt();
                }
                in.readNBytes(length - 8);                     // the rest of the startup message
                message(out, 'R', new byte[] {0, 0, 0, 0});    // AuthenticationOk
                for (String[] parameter : new String[][] {{"server_version", "16.4"},
                    {"client_encoding", "UTF8"}, {"standard_conforming_strings", "on"},
                    {"integer_datetimes", "on"}, {"DateStyle", "ISO, MDY"}, {"TimeZone", "UTC"}}) {
                    message(out, 'S', (parameter[0] + "\0" + parameter[1] + "\0")
                            .getBytes(StandardCharsets.US_ASCII));
                }
                message(out, 'K', new byte[] {0, 0, 0, 7, 0, 0, 0, 9});   // BackendKeyData
                message(out, 'Z', new byte[] {'I'});
                out.flush();
                // Whatever the query is: read up to its Sync or the simple Query.
                while (true) {
                    int type = in.read();
                    if (type < 0) {
                        return;
                    }
                    in.readNBytes(in.readInt() - 4);
                    if (type == 'S' || type == 'Q') {
                        break;
                    }
                }
                if (silent) {
                    while (!stop.get() && in.read() >= 0) {
                        // reads what comes - a second query - and answers nothing
                    }
                    return;
                }
                // A DataRow of a megabyte, a byte every 200 ms: never silent, never done.
                out.write('D');
                out.write(new byte[] {0, 16, 0, 0});
                out.flush();
                while (!stop.get()) {
                    out.write('x');
                    out.flush();
                    Thread.sleep(200);
                }
            } catch (IOException | InterruptedException gone) {
                // the client closed - what it should do
            }
        }

        private static void message(OutputStream out, char type, byte[] body) throws IOException {
            out.write(type);
            int length = body.length + 4;
            out.write(new byte[] {(byte) (length >>> 24), (byte) (length >>> 16),
                (byte) (length >>> 8), (byte) length});
            out.write(body);
        }

        @Override
        public void close() throws IOException {
            stop.set(true);
            listener.close();
        }
    }

    @Test
    void aServerIgnoringTheCancellationLosesTheConnectionWithinTimeoutAndGrace() throws Exception {
        long took = killedAfter(1);
        assertTrue(took < 6_000, "took " + took + " ms");
    }

    /** The grace is the setting: with two seconds the kill comes a second later. */
    @Test
    void theGraceIsConfigurable() throws Exception {
        long took = killedAfter(2);
        assertTrue(took >= 2_500 && took < 8_000, "took " + took + " ms with a grace of 2 s");
    }

    /**
     * The pool's capacity question to a server that says nothing: bounded by
     * seclume.pool.probeSeconds and the grace, the connection closed after it
     * - the pool must not lend it - and no capacity made up.
     */
    @Test
    void aCapacityProbeToASilentServerIsBoundedAndClosesTheConnection() throws Exception {
        String before = System.getProperty("seclume.queryTimeoutGraceSeconds");
        System.setProperty("seclume.queryTimeoutGraceSeconds", "1");
        java.lang.reflect.Field field = Class.forName("space.seclume.internal.jdbc.Capacities")
                .getDeclaredField("PROBE_SECONDS");
        field.setAccessible(true);
        int probeSeconds = field.getInt(null);
        try (TricklingPostgres server = new TricklingPostgres(true)) {
            SeclumeDataSource source = new SeclumeDataSource();
            source.setHost("127.0.0.1");
            source.setPort(server.listener.getLocalPort());
            source.setTls("off");
            source.setDatabase("app");
            source.setUser("app");
            source.setSecretProvider(new CallbackSecretProvider(16, target -> {
                target.set(ValueLayout.JAVA_BYTE, 0, (byte) 'x');
                return 1;
            }));
            try (Connection c = source.getConnection()) {
                long started = System.nanoTime();
                space.seclume.ServerCapacity.Capacity capacity =
                        c.unwrap(space.seclume.ServerCapacity.class).capacity();
                long took = (System.nanoTime() - started) / 1_000_000;
                assertTrue(capacity.allowed() < 0, "a capacity was made up: " + capacity);
                long bound = (probeSeconds + 1) * 1000L * 2 + 3000;   // two questions, each bounded
                assertTrue(took < bound, "took " + took + " ms, probeSeconds " + probeSeconds);
                assertTrue(c.isClosed() || !c.isValid(1), "the probed connection is still usable");
            }
        } finally {
            if (before == null) {
                System.clearProperty("seclume.queryTimeoutGraceSeconds");
            } else {
                System.setProperty("seclume.queryTimeoutGraceSeconds", before);
            }
        }
    }

    /** Runs the query against the trickling server with this grace; the milliseconds it took. */
    private static long killedAfter(int graceSeconds) throws Exception {
        String before = System.getProperty("seclume.queryTimeoutGraceSeconds");
        System.setProperty("seclume.queryTimeoutGraceSeconds", Integer.toString(graceSeconds));
        try (TricklingPostgres server = new TricklingPostgres()) {
            SeclumeDataSource source = new SeclumeDataSource();
            source.setHost("127.0.0.1");
            source.setPort(server.listener.getLocalPort());
            source.setTls("off");
            source.setDatabase("app");
            source.setUser("app");
            source.setSecretProvider(new CallbackSecretProvider(16, target -> {
                target.set(ValueLayout.JAVA_BYTE, 0, (byte) 'x');
                return 1;
            }));
            try (Connection c = source.getConnection(); Statement s = c.createStatement()) {
                s.setQueryTimeout(1);
                long started = System.nanoTime();
                SQLException ended = assertThrows(SQLException.class,
                        () -> s.executeQuery("select generate_series(1, 1000000000)").close());
                long took = (System.nanoTime() - started) / 1_000_000;
                assertTrue(c.isClosed() || !c.isValid(1), "the connection is still in use: " + ended);
                assertTrue(server.cancels.get() >= 1, "no cancellation was sent first");
                return took;
            }
        } finally {
            if (before == null) {
                System.clearProperty("seclume.queryTimeoutGraceSeconds");
            } else {
                System.setProperty("seclume.queryTimeoutGraceSeconds", before);
            }
        }
    }
}
