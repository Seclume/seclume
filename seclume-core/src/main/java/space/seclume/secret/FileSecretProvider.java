package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import space.seclume.internal.OffHeapIo;

/**
 * The secret sits in a file - the most common case in production.
 *
 * <p>Covers Docker and Kubernetes secret mounts ({@code /run/secrets/...}),
 * systemd {@code LoadCredential=}, and simply a file with tight permissions.
 *
 * <p>Reading goes through {@link FileChannel} into the direct buffer of the
 * target segment. {@code Files.readString} or {@code Files.readAllBytes} would
 * be the obvious choice here and exactly the mistake: both put the secret onto
 * the heap as a {@code byte[]} or {@code String}, where it stays until some
 * later GC happens to overwrite it - and forever in a heap dump.
 *
 * <p>A trailing newline is stripped. That is not convenience but necessity:
 * {@code echo secret > file} writes one, and a password with a {@code \n}
 * appended fails at the server with an error nobody can place.
 */
public final class FileSecretProvider implements SecretProvider {

    private final Path path;
    private final int maxLength;
    private final boolean trimLineBreak;

    public FileSecretProvider(Path path, int maxLength) {
        this(path, maxLength, true);
    }

    public FileSecretProvider(Path path, int maxLength, boolean trimLineBreak) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.path = path;
        this.maxLength = maxLength;
        this.trimLineBreak = trimLineBreak;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            int read = OffHeapIo.readFully(channel, target);
            if (read == target.byteSize() && OffHeapIo.hasMore(channel)) {
                throw new SecretUnavailableException(
                        "secret in " + path + " is longer than the configured "
                        + maxLength + " bytes");
            }
            int length = trimLineBreak ? OffHeapIo.trimLineBreak(target, read) : read;
            if (length == 0) {
                throw new SecretUnavailableException("secret in " + path + " is empty");
            }
            return length;
        } catch (IOException e) {
            // The path may go into the message, the content may not.
            throw new SecretUnavailableException("cannot read the secret from " + path, e);
        }
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "FileSecretProvider[path=" + path + "]";
    }
}
