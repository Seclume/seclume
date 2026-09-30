package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretScope;

/**
 * Off-heap Diffie-Hellman against {@link BigInteger} as the reference: the
 * public value and the shared secret, two parties agreeing, and the peer
 * values that would force a known secret refused.
 */
class DiffieHellmanTest {

    /** RFC 2409's first Oakley group, 768 bits - a well-known safe prime, generator 2. */
    private static final byte[] PRIME = HexFormat.of().parseHex(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
                    + "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576"
                    + "625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF");
    private static final byte[] GENERATOR = {2};

    @Test
    void twoPartiesAgreeAndMatchBigInteger() {
        try (Arena arena = Arena.ofConfined();
             DiffieHellman alice = group(arena, 32); DiffieHellman bob = group(arena, 96)) {
            int length = PRIME.length;
            MemorySegment alicePublic = arena.allocate(length);
            MemorySegment bobPublic = arena.allocate(length);
            alice.publicValue(alicePublic, 0);
            bob.publicValue(bobPublic, 0);
            try (SecretScope one = alice.sharedSecret(bobPublic, 0, length);
                 SecretScope two = bob.sharedSecret(alicePublic, 0, length)) {
                assertEquals(length, one.length());
                assertArrayEquals(bytes(one.segment(), length), bytes(two.segment(), length));
            }
        }
    }

    @Test
    void thePublicValueIsGeneratorToThePrivateExponent() {
        // A known exponent through the same arithmetic the class uses.
        byte[] exponent = HexFormat.of().parseHex("00c0ffee1234567890abcdef0000000000000001");
        try (Arena arena = Arena.ofConfined()) {
            int words = BigWords.wordCount(PRIME.length);
            MemorySegment prime = arena.allocate(words * 4L);
            MemorySegment base = arena.allocate(words * 4L);
            BigWords.fromBytes(MemorySegment.ofArray(PRIME), 0, PRIME.length, prime, words);
            BigWords.fromBytes(MemorySegment.ofArray(GENERATOR), 0, 1, base, words);
            MemorySegment result = arena.allocate(words * 4L);
            BigWords.modPowSecret(base, MemorySegment.ofArray(exponent), 0, exponent.length,
                    prime, words, result, arena);
            MemorySegment out = arena.allocate(PRIME.length);
            BigWords.toBytes(result, words, out, 0, PRIME.length);
            BigInteger expected = BigInteger.TWO.modPow(new BigInteger(1, exponent),
                    new BigInteger(1, PRIME));
            assertArrayEquals(fixed(expected, PRIME.length), bytes(out, PRIME.length));
        }
    }

    @Test
    void theSecretAndThePublicModPowAgree() {
        byte[] exponent = HexFormat.of().parseHex("7f000000000000000000000000000000000000000000000000000001");
        try (Arena arena = Arena.ofConfined()) {
            int words = BigWords.wordCount(PRIME.length);
            MemorySegment prime = arena.allocate(words * 4L);
            MemorySegment base = arena.allocate(words * 4L);
            BigWords.fromBytes(MemorySegment.ofArray(PRIME), 0, PRIME.length, prime, words);
            BigWords.fromBytes(MemorySegment.ofArray(new byte[] {5}), 0, 1, base, words);
            MemorySegment secret = arena.allocate(words * 4L);
            MemorySegment open = arena.allocate(words * 4L);
            BigWords.modPowSecret(base, MemorySegment.ofArray(exponent), 0, exponent.length,
                    prime, words, secret, arena);
            BigWords.modPow(base, MemorySegment.ofArray(exponent), 0, exponent.length, prime,
                    words, open, arena);
            assertEquals(-1, secret.asSlice(0, words * 4L).mismatch(open.asSlice(0, words * 4L)));
        }
    }

    @Test
    void peerValuesThatForceAKnownSecretAreRefused() {
        try (Arena arena = Arena.ofConfined(); DiffieHellman dh = group(arena, 32)) {
            int length = PRIME.length;
            BigInteger p = new BigInteger(1, PRIME);
            for (BigInteger bad : new BigInteger[] {BigInteger.ZERO, BigInteger.ONE,
                    p.subtract(BigInteger.ONE), p}) {
                MemorySegment value = MemorySegment.ofArray(fixed(bad, length));
                assertThrows(IllegalArgumentException.class,
                        () -> dh.sharedSecret(value, 0, length).close(), bad.toString(16));
            }
        }
    }

    private static DiffieHellman group(Arena arena, int exponentLength) {
        MemorySegment prime = arena.allocate(PRIME.length);
        MemorySegment.copy(PRIME, 0, prime, ValueLayout.JAVA_BYTE, 0, PRIME.length);
        MemorySegment generator = arena.allocate(1);
        generator.set(ValueLayout.JAVA_BYTE, 0, (byte) 2);
        return DiffieHellman.generate(prime, 0, PRIME.length, generator, 0, 1, exponentLength);
    }

    private static byte[] bytes(MemorySegment segment, int length) {
        return segment.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
    }

    private static byte[] fixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return Arrays.copyOf(out, length);
    }
}
