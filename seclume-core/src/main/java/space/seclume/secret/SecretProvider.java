package space.seclume.secret;

import java.lang.foreign.MemorySegment;

/**
 * The source of a database password.
 *
 * <p>There is deliberately no method that returns the secret as a value - no
 * {@code String}, no {@code char[]}, no {@code byte[]}. A return value would be
 * a heap object, and with it the password would stand in the heap dump; which
 * is exactly what this library exists to prevent. Instead the caller allocates
 * an off-heap segment and the provider writes into it.
 *
 * <p>The rule for implementations: on its way from the source into the target
 * segment, the secret must <b>never</b> pass through a heap object. That rules
 * out, among others: {@code Files.readString}, {@code Files.readAllBytes},
 * {@code InputStream.readAllBytes}, {@code new String(...)},
 * {@code String.getBytes()}, {@code Base64.getDecoder().decode(String)},
 * {@code System.getenv()} and {@code Properties}.
 *
 * <p>The provider is called again on <b>every</b> physical connect; neither the
 * driver nor the pool holds on to the result. That is what makes rotating the
 * secret take effect without a restart. Implementations therefore have to be
 * thread-safe and reusable.
 */
public interface SecretProvider extends AutoCloseable {

    /**
     * Writes the secret into {@code target} and returns the number of bytes
     * written.
     *
     * @throws SecretUnavailableException if the source cannot be read or the
     *         secret does not fit into {@code target}
     */
    int writeSecret(MemorySegment target);

    /**
     * Upper bound for the segment size the caller has to provide. The value may
     * be generous - it only decides the allocation.
     */
    int maxSecretLength();

    /** Releases the source's resources. The default does nothing. */
    @Override
    default void close() {
    }
}
