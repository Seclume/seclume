package space.seclume.secret;

import java.lang.foreign.MemorySegment;

import space.seclume.internal.OffHeapIo;

/**
 * Your own source as a lambda - for Vault, KMS, HSM, and for tests.
 *
 * <p>The lambda receives the target segment and returns the length it wrote.
 * It may do anything, as long as the secret does not pass through a heap
 * object; whoever uses {@code new String(...)} in here defeats the core
 * property, and the library has no way of noticing.
 */
public final class CallbackSecretProvider implements SecretProvider {

    /** Writes the secret and returns its length. */
    @FunctionalInterface
    public interface SecretWriter {
        int write(MemorySegment target);
    }

    private final SecretWriter writer;
    private final int maxLength;

    public CallbackSecretProvider(int maxLength, SecretWriter writer) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.maxLength = maxLength;
        this.writer = writer;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        int written = writer.write(target);
        if (written < 0 || written > target.byteSize()) {
            throw new SecretUnavailableException(
                    "callback reported an implausible secret length: " + written);
        }
        return written;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "CallbackSecretProvider[maxLength=" + maxLength + "]";
    }
}
