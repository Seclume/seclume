package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import space.seclume.internal.Entropy;
import space.seclume.secret.SecretScope;

/**
 * Finite-field Diffie-Hellman over a group the peer names - Oracle's Native
 * Network Encryption sends prime and generator with its own public value.
 *
 * <p>Off-heap throughout: the private exponent is random bytes in a
 * {@link SecretScope}, the arithmetic runs in {@link BigWords} with the
 * exponent handled in constant time ({@link BigWords#modPowSecret}), and the
 * shared secret - the session key material - comes back in a scope of its
 * own. {@link java.math.BigInteger} would leave every intermediate value on
 * the heap.
 */
public final class DiffieHellman implements AutoCloseable {

    private final MemorySegment prime;         // BigWords
    private final MemorySegment generator;     // BigWords
    private final int words;
    private final int length;                  // bytes of prime, public value and secret
    private final SecretScope exponent;
    private final Arena arena = Arena.ofShared();

    private DiffieHellman(MemorySegment prime, long primeOffset, MemorySegment generator,
                          long generatorOffset, int generatorLength, int length,
                          int exponentLength) {
        this.length = length;
        this.words = BigWords.wordCount(length);
        this.prime = arena.allocate(words * 4L);
        this.generator = arena.allocate(words * 4L);
        BigWords.fromBytes(prime, primeOffset, length, this.prime, words);
        BigWords.fromBytes(generator, generatorOffset, generatorLength, this.generator, words);
        this.exponent = SecretScope.allocateShared(exponentLength);
        Entropy.fill(exponent.segment(), 0, exponentLength);
        exponent.length(exponentLength);
    }

    /**
     * A fresh private exponent of {@code exponentLength} random bytes for the
     * group of {@code prime} ({@code length} big-endian bytes) and
     * {@code generator}.
     */
    public static DiffieHellman generate(MemorySegment prime, long primeOffset, int length,
                                         MemorySegment generator, long generatorOffset,
                                         int generatorLength, int exponentLength) {
        if (length <= 0 || generatorLength <= 0 || generatorLength > length
                || exponentLength <= 0) {
            throw new IllegalArgumentException("a Diffie-Hellman group of " + length
                    + " bytes with a generator of " + generatorLength + " bytes");
        }
        return new DiffieHellman(prime, primeOffset, generator, generatorOffset,
                generatorLength, length, exponentLength);
    }

    /** The length of the public value and of the shared secret, in bytes. */
    public int length() {
        return length;
    }

    /** {@code generator^exponent mod prime}, big-endian, {@link #length()} bytes - public. */
    public void publicValue(MemorySegment out, long offset) {
        try (Arena call = Arena.ofConfined()) {
            MemorySegment result = call.allocate(words * 4L);
            BigWords.modPowSecret(generator, exponent.segment(), 0, exponent.length(), prime,
                    words, result, call);
            BigWords.toBytes(result, words, out, offset, length);
        }
    }

    /**
     * {@code peer^exponent mod prime} - the shared secret, {@link #length()}
     * bytes big-endian, in a scope the caller closes.
     *
     * @throws IllegalArgumentException for a peer value of 0, 1 or p-1, or not
     *         below the prime - the values that force a known secret
     */
    public SecretScope sharedSecret(MemorySegment peer, long offset, int peerLength) {
        if (peerLength > length) {
            throw new IllegalArgumentException("the peer's public value has " + peerLength
                    + " bytes, the group " + length);
        }
        try (Arena call = Arena.ofConfined()) {
            MemorySegment value = call.allocate(words * 4L);
            BigWords.fromBytes(peer, offset, peerLength, value, words);
            MemorySegment limit = call.allocate(words * 4L);
            MemorySegment.copy(prime, 0, limit, 0, words * 4L);
            MemorySegment one = call.allocate(words * 4L);
            BigWords.setSmall(one, words, 1);
            BigWords.subtract(limit, one, words);                  // p - 1
            if (BigWords.compare(value, one, words) <= 0
                    || BigWords.compare(value, limit, words) >= 0) {
                throw new IllegalArgumentException("the peer's public value is outside 2 .. p-2");
            }
            MemorySegment result = call.allocate(words * 4L);
            try {
                BigWords.modPowSecret(value, exponent.segment(), 0, exponent.length(), prime,
                        words, result, call);
                SecretScope secret = SecretScope.allocateShared(length);
                BigWords.toBytes(result, words, secret.segment(), 0, length);
                secret.length(length);
                return secret;
            } finally {
                result.fill((byte) 0);
            }
        }
    }

    @Override
    public void close() {
        exponent.close();
        arena.close();
    }
}
