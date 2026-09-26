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
public final class SocketTransport implements Transport, NetworkTimeouts.Watched {

    private final SocketChannel channel;

    /** See {@link #networkTimeout}; 0 for none. */
    private volatile int timeoutMillis;
    /** When the current read or write began; 0 while nothing waits. */
    private volatile long busySince;
    /** Closed by the watch rather than by anybody else. */
    private volatile boolean timedOut;
    /** When bytes last went either way - for saying why a connection ended. */
    private volatile long lastTraffic = System.nanoTime();

    /**
     * Silence longer than this, then a broken connection: the failure says so,
     * because that is what an idle timeout somewhere in between looks like.
     */
    static volatile long quietMillis = 30_000;

    /** After this much silence the platform starts asking whether the peer is still there. */
    static final int KEEPALIVE_IDLE_SECONDS = 60;

    private SocketTransport(SocketChannel channel) {
        this.channel = channel;
    }

    /**
     * Opens a connection, with the socket options every driver wants.
     *
     * <p>{@code TCP_NODELAY} because a handshake consists of small messages
     * that have to leave at once - with Nagle each one waits for the next.
     *
     * <p>{@code SO_KEEPALIVE}, probing after a minute of silence where the
     * platform lets that be set: a pooled connection sits idle for minutes,
     * and every firewall, NAT and load balancer on the way forgets an idle
     * flow sooner or later - Azure's after four minutes - without telling
     * either end. The next statement then meets a connection that is gone,
     * as "Communications link failure" or "Got minus one from a read call".
     * A probe a minute keeps the flow alive in all of them, and finds a peer
     * that really went away.
     */
    public static SocketTransport connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        SocketChannel channel = SocketChannel.open();
        try {
            channel.socket().connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            channel.configureBlocking(true);
            channel.setOption(StandardSocketOptions.TCP_NODELAY, Boolean.TRUE);
            keepAlive(channel);
            return new SocketTransport(channel);
        } catch (IOException e) {
            channel.close();
            throw e;
        }
    }

    private static void keepAlive(SocketChannel channel) throws IOException {
        channel.setOption(StandardSocketOptions.SO_KEEPALIVE, Boolean.TRUE);
        java.util.Set<java.net.SocketOption<?>> supported = channel.supportedOptions();
        if (supported.contains(jdk.net.ExtendedSocketOptions.TCP_KEEPIDLE)) {
            channel.setOption(jdk.net.ExtendedSocketOptions.TCP_KEEPIDLE, KEEPALIVE_IDLE_SECONDS);
        }
        if (supported.contains(jdk.net.ExtendedSocketOptions.TCP_KEEPINTERVAL)) {
            channel.setOption(jdk.net.ExtendedSocketOptions.TCP_KEEPINTERVAL, 10);
        }
        if (supported.contains(jdk.net.ExtendedSocketOptions.TCP_KEEPCOUNT)) {
            channel.setOption(jdk.net.ExtendedSocketOptions.TCP_KEEPCOUNT, 5);
        }
    }

    /** Whether keepalive is on - for the tests. */
    boolean keepsAlive() throws IOException {
        return channel.getOption(StandardSocketOptions.SO_KEEPALIVE);
    }

    /**
     * What a connection that ended after a long silence says about it.
     *
     * @param end what the driver would have seen - null for an end of stream
     */
    private IOException afterSilence(long quietNanos, IOException end) {
        long seconds = quietNanos / 1_000_000_000L;
        return new IOException("the connection was cut after " + seconds + " s without "
                + "traffic - that matches an idle timeout between here and the server (a "
                + "firewall, a NAT, a load balancer) or the server's own (wait_timeout, "
                + "idle_session_timeout); keepalive probes after " + KEEPALIVE_IDLE_SECONDS
                + " s keep most of them from happening"
                + (end == null ? "" : ": " + end.getMessage()), end);
    }

    /** Wraps a channel somebody else opened - for tests over a loopback pair. */
    public static SocketTransport wrap(SocketChannel channel) {
        return new SocketTransport(channel);
    }

    @Override
    public int read(ByteBuffer into) throws IOException {
        long quiet = System.nanoTime() - lastTraffic;
        int read;
        if (timeoutMillis == 0) {
            try {
                read = channel.read(into);
            } catch (IOException e) {
                throw quiet > quietMillis * 1_000_000L ? afterSilence(quiet, e) : e;
            }
        } else {
            busySince = System.nanoTime();
            try {
                read = channel.read(into);
            } catch (IOException e) {
                throw timedOut ? timeout(e)
                        : quiet > quietMillis * 1_000_000L ? afterSilence(quiet, e) : e;
            } finally {
                busySince = 0;
            }
        }
        if (read < 0 && quiet > quietMillis * 1_000_000L) {
            // An end of stream after a long silence is not the server
            // finishing a conversation - it is somebody in between, or the
            // server, having given up on an idle connection.
            throw afterSilence(quiet, null);
        }
        if (read > 0) {
            lastTraffic = System.nanoTime();
        }
        return read;
    }

    @Override
    public int write(ByteBuffer from) throws IOException {
        long quiet = System.nanoTime() - lastTraffic;
        int written;
        if (timeoutMillis == 0) {
            try {
                written = channel.write(from);
            } catch (IOException e) {
                throw quiet > quietMillis * 1_000_000L ? afterSilence(quiet, e) : e;
            }
        } else {
            busySince = System.nanoTime();
            try {
                written = channel.write(from);
            } catch (IOException e) {
                throw timedOut ? timeout(e)
                        : quiet > quietMillis * 1_000_000L ? afterSilence(quiet, e) : e;
            } finally {
                busySince = 0;
            }
        }
        if (written > 0) {
            lastTraffic = System.nanoTime();
        }
        return written;
    }

    /**
     * Watched from now on: a read or write waiting longer than this closes
     * the connection. The blocking calls stay what they were; the waiting is
     * noticed by {@link NetworkTimeouts}, not measured here.
     */
    @Override
    public void networkTimeout(int millis) throws IOException {
        if (millis < 0) {
            throw new IOException("a network timeout cannot be negative: " + millis);
        }
        if (!channel.isOpen()) {
            throw new IOException("the connection is closed");
        }
        timeoutMillis = millis;
        NetworkTimeouts.watch(this, millis);
    }

    @Override
    public long busySince() {
        return busySince;
    }

    @Override
    public int timeoutMillis() {
        return timeoutMillis;
    }

    @Override
    public void expire() {
        timedOut = true;
        close();
    }

    private java.net.SocketTimeoutException timeout(IOException cause) {
        java.net.SocketTimeoutException timeout = new java.net.SocketTimeoutException(
                "no answer within the network timeout of " + timeoutMillis
                        + " ms - the connection was closed");
        timeout.initCause(cause);
        return timeout;
    }

    /**
     * Through the socket adaptor, which is the only route the JDK offers.
     *
     * <p>{@code SocketChannel} has no {@code sendUrgentData} of its own; the
     * adaptor {@link SocketChannel#socket()} returns does, and it reaches the
     * same descriptor. Measured rather than assumed - the adaptor declines
     * several things and this is not one of them.
     */
    @Override
    public void sendUrgent(int value) throws IOException {
        channel.socket().sendUrgentData(value);
    }

    @Override
    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() {
        NetworkTimeouts.forget(this);
        try {
            channel.close();
        } catch (IOException ignored) {
            // On close an error has no consequences.
        }
    }
}
