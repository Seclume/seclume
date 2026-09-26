package space.seclume.tck;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A real server, reachable through something that can be taken away.
 *
 * <p>Between a driver and a database there is nothing here but bytes in both
 * directions: it has to be transparent to four protocols, one of which is TLS
 * from the first byte, so it must not have an opinion about any of them. What
 * it adds is {@link #cut()} - the listener closes and every socket it is
 * relaying is dropped, which from inside a driver is indistinguishable from
 * the server going away.
 *
 * <p><b>Why this rather than a protocol fake.</b> A fake server is the right
 * tool for a failure the server produces - a rejected password, an error
 * token - because it can produce it exactly. It is the wrong tool for a
 * failure that has nothing to do with the protocol, because then the fake has
 * to be complete enough to reach the interesting moment, and a half-built
 * handshake is a test that passes for the wrong reason. Here the login is
 * real, all the way, and the only thing that is arranged is when it stops.
 *
 * <p>The timing worth arranging is usually not "after n bytes" but "while the
 * secret is in memory", which the caller can hit exactly: cut from inside the
 * callback of a {@code CallbackSecretProvider}, then return the password. The
 * driver then sends a credential into a connection that no longer exists,
 * which is the moment a wipe is most likely to be skipped.
 */
public final class BreakableRelay implements AutoCloseable {

    private final ServerSocket listener;
    private final String host;
    private final int port;
    private final List<Socket> open = new CopyOnWriteArrayList<>();
    private volatile boolean stopped;
    private volatile int connections;
    /** Milliseconds added to every block relayed - a stand-in for distance. */
    private volatile long delayMillis;
    /** Whether answers are swallowed instead of delivered - see swallowAnswers(). */
    private volatile boolean swallowing;

    private BreakableRelay(ServerSocket listener, String host, int port) {
        this.listener = listener;
        this.host = host;
        this.port = port;
        Thread.ofVirtual().name("relay-accept").start(this::accept);
    }

    /** Listens on the loopback and forwards to that server. */
    public static BreakableRelay to(String host, int port) throws IOException {
        // A test relay on the loopback address, for breaking connections on purpose.
        ServerSocket listener = new ServerSocket(); // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        return new BreakableRelay(listener, host, port);
    }

    /**
     * Adds latency to every block in both directions.
     *
     * <p>For measuring what pipelining is actually for. On a loopback
     * connection a round trip costs almost nothing, so a driver that sends
     * eight requests one after the other looks exactly as fast as one that
     * sends them together - and the difference the whole exercise is about
     * disappears into the noise. Ten milliseconds each way is an ordinary
     * distance between an application server and a database.
     *
     * <p>Per block rather than per byte, because that is what a network does:
     * the cost is the trip, not the payload.
     */
    public void delay(long millis) {
        this.delayMillis = millis;
    }

    /**
     * From now on the server's answers are dropped and the connection closed.
     *
     * <p>This produces the state nobody likes to think about and everybody has
     * to: the request reached the server and <b>was carried out</b>, the answer
     * never came back, and the client is left with an error and no way to know
     * whether the work happened. It is the reason a driver must not silently
     * repeat a statement, and it cannot be produced by cutting the connection
     * outright - that usually kills the request before it lands.
     *
     * <p>Requests keep flowing to the server; only the way back is closed.
     */
    public void swallowAnswers() {
        this.swallowing = true;
    }

    /** Where a driver should connect instead of the real server. */
    public int port() {
        return listener.getLocalPort();
    }

    /** How many connections have come in - evidence that the relay was used. */
    public int connections() {
        return connections;
    }

    private void accept() {
        while (!stopped) {
            Socket from;
            try {
                from = listener.accept();
            } catch (IOException closed) {
                return;
            }
            connections++;
            open.add(from);
            Socket to = new Socket(); // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
            try {
                to.connect(new InetSocketAddress(host, port), 5_000);
            } catch (IOException unreachable) {
                close(from);
                continue;
            }
            open.add(to);
            pump(from, to, false);   // client -> server
            pump(to, from, true);    // server -> client
        }
    }

    private void pump(Socket from, Socket to, boolean towardsTheClient) {
        Thread.ofVirtual().name("relay-pump").start(() -> {
            byte[] buffer = new byte[16 * 1024];
            try (InputStream in = from.getInputStream();
                    OutputStream out = to.getOutputStream()) {
                int read;
                while ((read = in.read(buffer)) > 0) {
                    if (towardsTheClient && swallowing) {
                        // The answer is thrown away and the client hung up on.
                        // The server has done the work and will never be able
                        // to say so.
                        return;
                    }
                    long wait = delayMillis;
                    if (wait > 0) {
                        Thread.sleep(wait);
                    }
                    out.write(buffer, 0, read);
                    out.flush();
                }
            } catch (IOException broken) {
                // Either end going away ends this direction, which is all
                // there is to say about it.
            } catch (InterruptedException stopping) {
                Thread.currentThread().interrupt();
            } finally {
                close(from);
                close(to);
            }
        });
    }

    /** The server goes away, taking every connection through it. */
    public void cut() throws IOException {
        stopped = true;
        listener.close();
        for (Socket socket : open) {
            close(socket);
        }
        open.clear();
    }

    private static void close(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Closing twice is how this is used.
        }
    }

    @Override
    public void close() throws IOException {
        if (!stopped) {
            cut();
        }
    }
}
