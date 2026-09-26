package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * An expanded AES key, entirely off-heap.
 *
 * <p>The round keys can be derived from the key and the other way round -
 * whoever has them has the key. They therefore live in their own {@link Arena}
 * and are zeroed on close. {@link javax.crypto.spec.SecretKeySpec} is ruled out
 * for the same reason: it holds the key as a {@code byte[]}.
 */
public final class AesKey implements AutoCloseable {

    /**
     * Shared, not confined: a record layer's key lives as long as its
     * connection, and a connection is opened in one thread and used in
     * others - every pool does that. A confined arena made every connection
     * on seclume's own TLS stack fail with {@code WrongThreadException} the
     * first time a second thread touched it. Closing a shared arena costs a
     * little more; it happens a few times per connection, not per record.
     */
    private final Arena arena = Arena.ofShared();
    private final MemorySegment roundKeys;
    private final int rounds;
    private boolean closed;

    /**
     * @param key the key material, 16, 24 or 32 bytes from {@code offset}
     */
    public AesKey(MemorySegment key, long offset, int length) {
        int words = switch (length) {
            case 16 -> 4;
            case 24 -> 6;
            case 32 -> 8;
            default -> throw new IllegalArgumentException(
                    "AES key must be 16, 24 or 32 bytes, got " + length);
        };
        this.rounds = words + 6;
        int total = 4 * (rounds + 1);
        this.roundKeys = arena.allocate(total * 4L);

        for (int i = 0; i < words; i++) {
            roundKeys.set(BlockDigest.BE_INT, i * 4L, key.get(BlockDigest.BE_INT, offset + i * 4L));
        }
        for (int i = words; i < total; i++) {
            int temp = roundKeys.get(BlockDigest.BE_INT, (i - 1) * 4L);
            if (i % words == 0) {
                temp = substituteWord(Integer.rotateLeft(temp, 8)) ^ AesTables.RCON[i / words];
            } else if (words > 6 && i % words == 4) {
                temp = substituteWord(temp);
            }
            roundKeys.set(BlockDigest.BE_INT, i * 4L,
                    roundKeys.get(BlockDigest.BE_INT, (i - words) * 4L) ^ temp);
        }
    }

    /** The whole key of the segment. */
    public AesKey(MemorySegment key) {
        this(key, 0, (int) key.byteSize());
    }

    int rounds() {
        return rounds;
    }

    MemorySegment roundKeys() {
        if (closed) {
            throw new IllegalStateException("this AES key is closed - its memory was wiped, build a new one");
        }
        return roundKeys;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        roundKeys.fill((byte) 0);
        arena.close();
    }

    @Override
    public String toString() {
        return "AesKey[bits=" + ((rounds - 6) * 32) + "]";
    }

    /** SubWord - computed in constant time, see AesSubBytes: the input is key material. */
    private static int substituteWord(int word) {
        return AesSubBytes.word(word);
    }
}
