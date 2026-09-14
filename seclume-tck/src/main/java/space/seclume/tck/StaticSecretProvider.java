package space.seclume.tck;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretUnavailableException;

/**
 * UNSAFE - deliberately. Only as a negative control.
 *
 * <p>Holds the secret as a {@code String} <b>and</b> as a {@code byte[]} on the
 * heap, exactly the way an ordinary driver does. It thereby defeats the core
 * property of the library completely.
 *
 * <p>That is precisely why it exists: without a run in which the heap dump test
 * <b>finds</b> the password, a green run proves nothing at all - it might just
 * as well mean the search is broken. This class lives in the TCK module and is
 * never shipped with an application.
 */
public final class StaticSecretProvider implements SecretProvider {

    /** The leak, in two flavours. */
    private final String secretAsString;
    private final byte[] secretAsBytes;

    public StaticSecretProvider(String secret) {
        this.secretAsString = secret;
        // seclume-allow: this class is the negative control - it leaks the secret on purpose, so that a green heap-dump run proves the search works
        this.secretAsBytes = secret.getBytes(StandardCharsets.UTF_8);
    }

    /** Reads the file the way an ordinary driver would. */
    public static StaticSecretProvider fromFile(Path path) {
        try {
            // seclume-allow: see above - leaking is the point of this class
            return new StaticSecretProvider(Files.readString(path, StandardCharsets.UTF_8).strip());
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot read " + path, e);
        }
    }

    @Override
    public int writeSecret(MemorySegment target) {
        if (secretAsBytes.length > target.byteSize()) {
            throw new SecretUnavailableException("secret does not fit");
        }
        MemorySegment.copy(MemorySegment.ofArray(secretAsBytes), 0, target, 0,
                secretAsBytes.length);
        return secretAsBytes.length;
    }

    @Override
    public int maxSecretLength() {
        return Math.max(secretAsBytes.length, 1);
    }

    /** Keeps the optimiser from optimising the leak away. */
    public int leakLength() {
        return secretAsString.length() + secretAsBytes.length;
    }
}
