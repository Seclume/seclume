package space.seclume.bench;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

/**
 * A TCP forwarder, to find out what one costs.
 *
  * <p>Since 16.09.2026 the
 * measurement that decides more than it was meant to. The migration design
 * assumed this library owns its TLS state; it does not - it uses an
 * {@code SSLEngine}, whose keys and record sequence numbers no public API hands
 * out. One way around that is to put a relay beside the database: the driver's
 * connection to the relay carries no TLS, so a connection that moves has no TLS
 * state to move.
 *
 * <p>That road is only worth anything if the extra hop is cheap. This is the
 * thing to measure it with: deliberately the shape a real relay would have -
 * blocking channels, a thread per direction, {@code TCP_NODELAY} on both sides,
 * and a direct buffer that is allocated once - rather than the shape that
 * flatters it.
 *
 * <p>It is a measuring instrument, not a product. No TLS, no lease table, no
 * routing, and one target for every caller.
 *
 * <pre>
 * java -cp seclume-bench.jar space.seclume.bench.Relay 6543 127.0.0.1 5432
 * </pre>
 */
public final class Relay {

    private Relay() {
    }

    private static final int BUFFER = 64 * 1024;

    public static void main(String[] args) throws Exception {
        int listenPort = Integer.parseInt(args[0]);
        String targetHost = args[1];
        int targetPort = Integer.parseInt(args[2]);

        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(listenPort), 128);
            System.out.println("relay on " + listenPort + " -> " + targetHost + ":" + targetPort);
            while (true) {
                SocketChannel client = listener.accept();
                Thread.ofVirtual().start(() -> serve(client, targetHost, targetPort));
            }
        }
    }

    private static void serve(SocketChannel client, String host, int port) {
        try {
            SocketChannel server = SocketChannel.open(new InetSocketAddress(host, port));
            client.setOption(StandardSocketOptions.TCP_NODELAY, Boolean.TRUE);
            server.setOption(StandardSocketOptions.TCP_NODELAY, Boolean.TRUE);
            // One thread per direction: the two are independent, and a relay
            // that waits for a request before reading an answer would add a
            // round trip of its own to every exchange.
            Thread back = Thread.ofVirtual().start(() -> pump(server, client));
            pump(client, server);
            back.join();
        } catch (Exception ignored) {
            // A relay that logs every dropped connection is a relay nobody can
            // read the output of.
        } finally {
            close(client);
        }
    }

    private static void pump(SocketChannel from, SocketChannel to) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(BUFFER);
        try {
            while (true) {
                buffer.clear();
                if (from.read(buffer) < 0) {
                    break;
                }
                buffer.flip();
                while (buffer.hasRemaining()) {
                    to.write(buffer);
                }
            }
        } catch (IOException ignored) {
            // Either end going away is the ordinary way this ends.
        } finally {
            close(from);
            close(to);
        }
    }

    private static void close(SocketChannel channel) {
        try {
            channel.close();
        } catch (IOException ignored) {
            // Nothing to do about it.
        }
    }
}
