package space.seclume.tls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;

/**
 * The TLS 1.2 pseudo-random function (RFC 5246, section 5) - the one piece of
 * key schedule TLS 1.2 has, and the reason the master secret, the key block and
 * both Finished values can stay in native memory.
 *
 * <p>{@code PRF(secret, label, seed) = P_hash(secret, label + seed)}, where
 * {@code P_hash} chains HMAC: {@code A(0) = seed}, {@code A(i) = HMAC(secret,
 * A(i-1))}, and each output block is {@code HMAC(secret, A(i) + seed)}. The hash
 * is the cipher suite's: SHA-256, or SHA-384 for the {@code _SHA384} suites.
 *
 * <p>Nothing about it is clever, and that is the point of having it here: an
 * HMAC chain over our own {@link Hmac}, whose key lives in native memory and is
 * wiped on close. The chaining value {@code A(i)} depends on the secret and is
 * wiped as well; the label and seed are public - two randoms, or a transcript
 * hash.
 */
public final class Tls12Prf {

    private Tls12Prf() {
    }

    /**
     * Writes {@code length} bytes of {@code PRF(secret, label, seed)} to
     * {@code out}.
     *
     * @param seed the seed after the label - the two randoms, or a transcript
     *             hash; may be several segments, used in order
     */
    public static void derive(HashAlgorithm hash, MemorySegment secret, String label,
            MemorySegment[] seed, MemorySegment out, long outOffset, int length) {
        if (length < 0) {
            throw new IllegalArgumentException("a negative PRF length");
        }
        int digest = hash.digestLength();
        long seedLength = label.length();
        for (MemorySegment part : seed) {
            seedLength += part.byteSize();
        }
        try (Arena arena = Arena.ofConfined();
                Hmac mac = new Hmac(hash, secret)) {
            MemorySegment labelAndSeed = arena.allocate(seedLength);
            long at = 0;
            for (int i = 0; i < label.length(); i++) {
                labelAndSeed.set(ValueLayout.JAVA_BYTE, at++, (byte) label.charAt(i));
            }
            for (MemorySegment part : seed) {
                MemorySegment.copy(part, 0, labelAndSeed, at, part.byteSize());
                at += part.byteSize();
            }
            MemorySegment chain = arena.allocate(digest);
            MemorySegment block = arena.allocate(digest);
            try {
                mac.update(labelAndSeed);
                mac.doFinal(chain, 0);                       // A(1)
                int produced = 0;
                while (produced < length) {
                    mac.update(chain);
                    mac.update(labelAndSeed);
                    mac.doFinal(block, 0);
                    int take = Math.min(digest, length - produced);
                    MemorySegment.copy(block, 0, out, outOffset + produced, take);
                    produced += take;
                    if (produced < length) {
                        mac.update(chain);
                        mac.doFinal(chain, 0);               // A(i + 1)
                    }
                }
            } finally {
                chain.fill((byte) 0);
                block.fill((byte) 0);
            }
        }
    }

    /** The same with one seed segment. */
    public static void derive(HashAlgorithm hash, MemorySegment secret, String label,
            MemorySegment seed, MemorySegment out, long outOffset, int length) {
        derive(hash, secret, label, new MemorySegment[] {seed}, out, outOffset, length);
    }
}
