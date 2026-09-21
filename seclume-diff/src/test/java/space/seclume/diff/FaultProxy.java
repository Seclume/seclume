package space.seclume.diff;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A relay between a driver and a real server, able to break.
 *
 * <p>The fuzz tests point a driver at something that never was a server. This
 * is the other half: a <b>real</b> session, properly authenticated and doing
 * real work, into which a fault is introduced part way through. That is where
 * "it works" and "it is correct" come apart - a driver that answers correctly
 * when nothing goes wrong says nothing about what it does when something
 * does, and everything in these four protocols was written against servers
 * that behave.
 *
 * <p>Three faults, each with a question of its own:
 *
 * <ul>
 *   <li><b>Cut</b> - the connection dies mid-stream. The driver must raise a
 *       {@code SQLException}. What it must <i>not</i> do is hand back the
 *       rows it happened to receive as though the query had finished, which
 *       is silent data loss and the worst outcome a driver has available.
 *   <li><b>Fragment</b> - every byte in its own write. Nothing about the
 *       answer may change. A reassembly that works only because the operating
 *       system usually delivers a whole message at once is a reassembly that
 *       fails under load, on a slow link, or behind any proxy.
 *   <li><b>Pass through</b> - the control. Without it a green run proves only
 *       that the proxy broke everything equally.
 * </ul>
 */
final class FaultProxy implements AutoCloseable {

    enum Mode {
        /** Relay unchanged - the control. */
        PASS,
        /** One byte per write, in both directions. */
        FRAGMENT,
        /** Relay until {@link #cutNow()} or the byte budget runs out, then drop. */
        CUT
    }

    private final ServerSocket listener;
    private final String host;
    private final int port;
    private final Mode mode;
    private final AtomicLong bytesFromServerBeforeCut = new AtomicLong(Long.MAX_VALUE);
    private final AtomicBoolean cut = new AtomicBoolean();
    private final AtomicLong relayed = new AtomicLong();
    private final List<Socket> open = new CopyOnWriteArrayList<>();
    private volatile boolean stopped;

    FaultProxy(String host, int port, Mode mode) throws IOException {
        this.host = host;
        this.port = port;
        this.mode = mode;
        this.listener = new ServerSocket();
        this.listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        this.listener.setSoTimeout(30_000);

        Thread acceptor = new Thread(this::accept, "fault-proxy");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    /** Drop the connection once this many bytes have come back from the server. */
    FaultProxy cutAfterServerBytes(long bytes) {
        bytesFromServerBeforeCut.set(bytes);
        return this;
    }

    /** Drop it now, from another thread, while a query is in flight. */
    void cutNow() {
        cut.set(true);
        for (Socket socket : open) {
            try {
                socket.setSoLinger(true, 0);    // a reset, not a polite close
                socket.close();
            } catch (IOException alreadyGone) {
                // Nothing to do: the point was to break it.
            }
        }
    }

    int port() {
        return listener.getLocalPort();
    }

    /** How many bytes the server has sent through - for a test that wants to aim. */
    long relayedFromServer() {
        return relayed.get();
    }

    private void accept() {
        while (!stopped) {
            try {
                Socket client = listener.accept();
                Socket server = new Socket(host, port);
                open.add(client);
                open.add(server);
                pump(client, server, false);    // client -> server
                pump(server, client, true);     // server -> client
            } catch (IOException e) {
                if (stopped) {
                    return;
                }
            }
        }
    }

    private void pump(Socket from, Socket to, boolean fromServer) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[16 * 1024];
            try (InputStream in = from.getInputStream();
                 OutputStream out = to.getOutputStream()) {
                int read;
                while (!cut.get() && (read = in.read(buffer)) > 0) {
                    if (fromServer
                            && relayed.addAndGet(read) > bytesFromServerBeforeCut.get()) {
                        cutNow();
                        return;
                    }
                    if (mode == Mode.FRAGMENT) {
                        // One byte at a time, flushed each time: the driver
                        // sees the message arrive in pieces, which is what a
                        // real network does under load and what a reassembler
                        // is for.
                        for (int i = 0; i < read; i++) {
                            out.write(buffer[i]);
                            out.flush();
                        }
                    } else {
                        out.write(buffer, 0, read);
                        out.flush();
                    }
                }
            } catch (IOException broken) {
                // Either end may go first; both are ordinary here.
            } finally {
                closeQuietly(from);
                closeQuietly(to);
            }
        }, "fault-proxy-" + (fromServer ? "down" : "up"));
        thread.setDaemon(true);
        thread.start();
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException alreadyGone) {
            // Expected on the losing side of a race.
        }
    }

    @Override
    public void close() throws IOException {
        stopped = true;
        for (Socket socket : open) {
            closeQuietly(socket);
        }
        listener.close();
    }
}
