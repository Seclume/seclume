package space.seclume.internal;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * The {@link Transport} every driver has been using all along, now behind the
 * interface: a blocking {@link SocketChannel}.
 *
 * <p>This is the implementation to compare the FFM one against, and the one to
 * fall back to. It stays the default for as long as the other has not earned
 * the place by measurement - the design note claims the syscall route brings
 * buffers that never pass through the Java heap and one indirection fewer on
 * the hot path, and a claim of that shape is exactly what this project does not
 * take on trust.
 */
public final class SocketTransport implements Transport {

    private final SocketChannel channel;

    private SocketTransport(SocketChannel channel) {
        this.channel = channel;
    }

    /**
     * Opens a connection, with the socket options every driver wants.
     *
     * <p>{@code TCP_NODELAY} because a handshake consists of small messages
     * that have to leave at once - with Nagle each one waits for the next.
     */
    public static SocketTransport connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        SocketChannel channel = SocketChannel.open();
        try {
            channel.socket().connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            channel.configureBlocking(true);
            channel.setOption(StandardSocketOptions.TCP_NODELAY, Boolean.TRUE);
            return new SocketTransport(channel);
        } catch (IOException e) {
            channel.close();
            throw e;
        }
    }

    /** Wraps a channel somebody else opened - for tests over a loopback pair. */
    public static SocketTransport wrap(SocketChannel channel) {
        return new SocketTransport(channel);
    }

    @Override
    public int read(ByteBuffer into) throws IOException {
        return channel.read(into);
    }

    @Override
    public int write(ByteBuffer from) throws IOException {
        return channel.write(from);
    }

    @Override
    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException ignored) {
            // On close an error has no consequences.
        }
    }
}
