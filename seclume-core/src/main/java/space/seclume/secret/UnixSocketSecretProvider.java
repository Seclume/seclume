package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import space.seclume.internal.OffHeapIo;

/**
 * The secret arrives over a Unix domain socket - Vault agent, sidecar, or your
 * own credential daemon.
 *
 * <p>Compared to a file this has the advantage that the secret never sits on a
 * file system at all, not even in a tmpfs mount. Reading again goes straight
 * into the direct buffer of the target segment.
 *
 * <p>Optionally a request line is sent first - many agents want to know which
 * secret is meant. That line is not a secret and may therefore arrive as a
 * {@code String}.
 *
 * <p>The agent answers with the secret and closes the connection; the whole
 * answer has to arrive within the timeout (ten seconds unless given). An agent
 * that keeps the connection open, or never answers, is refused at the
 * timeout - it used to hold the caller for ever.
 */
public final class UnixSocketSecretProvider implements SecretProvider {

    /** How long the whole answer may take unless said otherwise. */
    public static final int DEFAULT_TIMEOUT_MILLIS = 10_000;

    private final Path socketPath;
    private final String request;
    private final int maxLength;
    private final int timeoutMillis;

    public UnixSocketSecretProvider(Path socketPath, String request, int maxLength) {
        this(socketPath, request, maxLength, DEFAULT_TIMEOUT_MILLIS);
    }

    public UnixSocketSecretProvider(Path socketPath, String request, int maxLength,
            int timeoutMillis) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        if (timeoutMillis <= 0) {
            throw new IllegalArgumentException("timeoutMillis must be positive");
        }
        this.socketPath = socketPath;
        this.request = request;
        this.maxLength = maxLength;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        try (SocketChannel channel = SocketChannel.open(UnixDomainSocketAddress.of(socketPath))) {
            if (request != null && !request.isEmpty()) {
                // seclume-allow: the request line names the secret, it is not the secret
                ByteBuffer out = ByteBuffer.wrap(request.getBytes(StandardCharsets.UTF_8));
                while (out.hasRemaining()) {
                    channel.write(out);
                }
            }
            int read = readUntilClosed(channel, target);
            int length = OffHeapIo.trimLineBreak(target, read);
            if (length == 0) {
                throw new SecretUnavailableException("the agent on " + socketPath + " sent nothing");
            }
            return length;
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot talk to the agent on " + socketPath, e);
        }
    }

    /**
     * Everything up to the end of the stream, into {@code target} (a direct
     * buffer over native memory), by the deadline - a blocking read has no
     * timeout of its own.
     */
    private int readUntilClosed(SocketChannel channel, MemorySegment target) throws IOException {
        long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
        channel.configureBlocking(false);
        java.nio.ByteBuffer buffer = target.asByteBuffer();
        java.nio.ByteBuffer probe = java.nio.ByteBuffer.allocateDirect(1);
        int total = 0;
        try (java.nio.channels.Selector selector = java.nio.channels.Selector.open()) {
            channel.register(selector, java.nio.channels.SelectionKey.OP_READ);
            while (true) {
                // Once the target is full, one byte more says it was too long.
                int read = buffer.hasRemaining() ? channel.read(buffer) : channel.read(probe);
                if (read < 0) {
                    return total;
                }
                if (read > 0) {
                    if (probe.position() > 0) {
                        target.fill((byte) 0);
                        throw new SecretUnavailableException("the agent on " + socketPath
                                + " sent more than the configured " + maxLength + " bytes");
                    }
                    total += read;
                    continue;
                }
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    target.fill((byte) 0);
                    throw new SecretUnavailableException("the agent on " + socketPath
                            + " did not answer and close the connection within "
                            + timeoutMillis + " ms");
                }
                selector.select(Math.max(1, left / 1_000_000));
                selector.selectedKeys().clear();
            }
        }
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "UnixSocketSecretProvider[socket=" + socketPath + "]";
    }
}
