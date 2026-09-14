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
 */
public final class UnixSocketSecretProvider implements SecretProvider {

    private final Path socketPath;
    private final String request;
    private final int maxLength;

    public UnixSocketSecretProvider(Path socketPath, String request, int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.socketPath = socketPath;
        this.request = request;
        this.maxLength = maxLength;
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
            int read = OffHeapIo.readFully(channel, target);
            if (read == target.byteSize() && OffHeapIo.hasMore(channel)) {
                throw new SecretUnavailableException(
                        "the agent on " + socketPath + " sent more than the configured "
                        + maxLength + " bytes");
            }
            int length = OffHeapIo.trimLineBreak(target, read);
            if (length == 0) {
                throw new SecretUnavailableException("the agent on " + socketPath + " sent nothing");
            }
            return length;
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot talk to the agent on " + socketPath, e);
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
