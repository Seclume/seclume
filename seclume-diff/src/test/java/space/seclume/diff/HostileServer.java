package space.seclume.diff;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * A server that answers a connection with whatever it likes.
 *
 * <p>Every test in this project so far has pointed a driver at something that
 * behaves - a real server, or a fake one written to be correct. That leaves
 * the whole of each handshake parser exercised only on input it expects, and
 * those four parsers were written from scratch. The bytes that arrive before
 * authentication are also the ones an attacker reaches first: anything able to
 * answer on the port, or to stand in the middle of the connection, is talking
 * to that code with no credential of any kind.
 *
 * <p>So this one misbehaves on purpose. It accepts, writes a scripted or
 * generated sequence, and closes - and the question is only ever whether the
 * driver fails <b>cleanly</b>: an ordinary {@code SQLException}, promptly,
 * without an {@code OutOfMemoryError}, without hanging, and without an
 * exception from somewhere deep that no caller could have expected.
 *
 * <p>The connection is closed after the bytes go out, on purpose. A server
 * that declares a huge length and then simply stops is not misbehaving in an
 * interesting way - every driver blocks there and should. Closing turns the
 * same case into "the length was a lie", which is the one worth testing.
 */
final class HostileServer implements AutoCloseable {

    private final ServerSocket socket;
    private final Thread thread;
    private final AtomicReference<Exception> failure = new AtomicReference<>();
    private volatile boolean stopped;

    /**
     * @param script what to write to each connection before closing it; it
     *               may also read first, for a protocol where the client
     *               speaks before the server does
     */
    HostileServer(Consumer<Socket> script) throws IOException {
        this.socket = new ServerSocket();
        this.socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        this.socket.setSoTimeout(30_000);
        this.thread = new Thread(() -> {
            while (!stopped) {
                try (Socket accepted = this.socket.accept()) {
                    accepted.setSoTimeout(10_000);
                    accepted.setSoLinger(true, 0);
                    script.accept(accepted);
                } catch (Exception e) {
                    if (stopped) {
                        return;
                    }
                    failure.set(e);
                }
            }
        }, "hostile-server");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    /** Writes bytes and lets the connection close behind them. */
    static Consumer<Socket> writing(byte[] bytes) {
        return socket -> {
            try {
                OutputStream out = socket.getOutputStream();
                out.write(bytes);
                out.flush();
            } catch (IOException hungUp) {
                // The driver gave up first, which is a perfectly good answer.
            }
        };
    }

    /**
     * Gives the client a moment to speak first, then writes the bytes.
     *
     * <p>A moment, not forever. Who speaks first differs by protocol -
     * PostgreSQL and TDS open with a request from the client, MySQL and
     * Oracle are greeted by the server - and waiting unconditionally turns
     * the server-speaks-first protocols into a standoff where both sides sit
     * in a read. The first run of this test spent its whole budget in exactly
     * that, and reported the drivers as hanging when it was the harness.
     *
     * <p>A sixth of a second. A client that opens the conversation does so
     * at once on a loopback socket; one that does not costs this per case,
     * and there are hundreds of cases - at half a second the MySQL run alone
     * took three quarters of a minute of pure waiting.
     */
    static Consumer<Socket> readingThenWriting(byte[] bytes) {
        return socket -> {
            try {
                socket.setSoTimeout(150);
                try {
                    socket.getInputStream().read(new byte[4096]);
                } catch (java.net.SocketTimeoutException silentClient) {
                    // This protocol has the server speak first. Carry on.
                }
                OutputStream out = socket.getOutputStream();
                out.write(bytes);
                out.flush();
            } catch (IOException hungUp) {
                // Same.
            }
        };
    }

    int port() {
        return socket.getLocalPort();
    }

    Exception serverFailure() {
        return failure.get();
    }

    @Override
    public void close() throws IOException {
        stopped = true;
        socket.close();
    }
}
