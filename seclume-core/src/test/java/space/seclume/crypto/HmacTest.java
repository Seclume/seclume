package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.HexFormat;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import space.seclume.Segments;

/** RFC 2202 (MD5, SHA-1) and RFC 4231 (SHA-256, SHA-512), plus a JCA cross-check. */
class HmacTest {

    @Test
    void rfc2202Case1() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = Segments.ascii(arena, "Hi There");
            // RFC 2202 uses a 16 byte key for MD5 and a 20 byte one for
            // SHA-1 - same case number, two lengths.
            assertEquals("9294727a3638bb1c13f48ef8158bfc9d",
                    mac(HashAlgorithm.MD5, Segments.repeated(arena, 0x0b, 16), data));
            assertEquals("b617318655057264e28bc0b6fb378c8ef146be00",
                    mac(HashAlgorithm.SHA_1, Segments.repeated(arena, 0x0b, 20), data));
        }
    }

    @Test
    void rfc4231Case1() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = Segments.repeated(arena, 0x0b, 20);
            MemorySegment data = Segments.ascii(arena, "Hi There");
            assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                    mac(HashAlgorithm.SHA_256, key, data));
            assertEquals("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                    + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
                    mac(HashAlgorithm.SHA_512, key, data));
        }
    }

    @Test
    void rfc4231Case2() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = Segments.ascii(arena, "Jefe");
            MemorySegment data = Segments.ascii(arena, "what do ya want for nothing?");
            assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                    mac(HashAlgorithm.SHA_256, key, data));
        }
    }

    /** A key longer than the block - the branch that hashes it first. */
    @Test
    void rfc4231Case6() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = Segments.repeated(arena, 0xaa, 131);
            MemorySegment data = Segments.ascii(arena,
                    "Test Using Larger Than Block-Size Key - Hash Key First");
            assertEquals("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                    mac(HashAlgorithm.SHA_256, key, data));
        }
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void matchesJca(HashAlgorithm algorithm) throws Exception {
        Random random = new Random(20260905L);
        Mac reference = Mac.getInstance(jcaName(algorithm));
        try (Arena arena = Arena.ofConfined()) {
            // Key lengths around the block boundary, data in all sizes.
            for (int keyLength : new int[] {1, 16, 20, 32, 63, 64, 65, 127, 128, 129, 200}) {
                for (int dataLength : new int[] {0, 1, 55, 64, 128, 1000}) {
                    byte[] key = new byte[keyLength];
                    byte[] data = new byte[dataLength];
                    random.nextBytes(key);
                    random.nextBytes(data);

                    reference.init(new SecretKeySpec(key, jcaName(algorithm)));
                    String expected = HexFormat.of().formatHex(reference.doFinal(data));

                    MemorySegment keySegment = Segments.bytes(arena, key);
                    MemorySegment dataSegment = Segments.bytes(arena, data);
                    assertEquals(expected, mac(algorithm, keySegment, dataSegment),
                            algorithm + " key=" + keyLength + " data=" + dataLength);
                }
            }
        }
    }

    /** After {@code doFinal} the same key stands ready again. */
    @Test
    void reusableWithSameKey() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = Segments.ascii(arena, "key");
            MemorySegment data = Segments.ascii(arena, "message");
            MemorySegment first = arena.allocate(32);
            MemorySegment second = arena.allocate(32);
            try (Hmac hmac = new Hmac(HashAlgorithm.SHA_256, key)) {
                hmac.update(data);
                hmac.doFinal(first, 0);
                hmac.update(data);
                hmac.doFinal(second, 0);
            }
            assertEquals(Segments.toHex(first), Segments.toHex(second));
        }
    }

    /**
     * The padded key is hashed once and its hash state restored on every
     * {@code doFinal} (28.09.2026, for PBKDF2's speed). That has to give the
     * same MAC as hashing the pads each time: across keys shorter than, equal
     * to and longer than the block, messages split at arbitrary points, and
     * one object used for several messages in a row - the part the saved
     * state exists for.
     */
    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void theSavedPadStateMatchesJcaOnEveryReuse(HashAlgorithm algorithm) throws Exception {
        Random random = new Random(20260928L + algorithm.ordinal());
        int block = algorithm.blockLength();
        for (int keyLength : new int[] {1, block - 1, block, block + 1, 2 * block + 3}) {
            byte[] key = new byte[keyLength];
            random.nextBytes(key);
            Mac jca = Mac.getInstance(jcaName(algorithm));
            jca.init(new SecretKeySpec(key, jcaName(algorithm)));
            try (Arena arena = Arena.ofConfined();
                 Hmac hmac = new Hmac(algorithm, copy(arena, key))) {
                for (int message = 0; message < 5; message++) {
                    byte[] data = new byte[random.nextInt(3 * block)];
                    random.nextBytes(data);
                    int cut = data.length == 0 ? 0 : random.nextInt(data.length);
                    hmac.update(copy(arena, java.util.Arrays.copyOfRange(data, 0, cut)));
                    hmac.update(copy(arena, java.util.Arrays.copyOfRange(data, cut, data.length)));
                    MemorySegment out = arena.allocate(algorithm.digestLength());
                    hmac.doFinal(out, 0);
                    assertEquals(HexFormat.of().formatHex(jca.doFinal(data)), Segments.toHex(out),
                            algorithm + ", key of " + keyLength + " bytes, message " + message);
                }
            }
        }
    }

    private static MemorySegment copy(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(1, bytes.length)).asSlice(0, bytes.length);
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
        return segment;
    }

    private static String mac(HashAlgorithm algorithm, MemorySegment key, MemorySegment data) {
        try (Arena arena = Arena.ofConfined();
             Hmac hmac = new Hmac(algorithm, key)) {
            MemorySegment out = arena.allocate(algorithm.digestLength());
            hmac.update(data);
            hmac.doFinal(out, 0);
            return Segments.toHex(out);
        }
    }

    private static String jcaName(HashAlgorithm algorithm) {
        return switch (algorithm) {
            case MD5 -> "HmacMD5";
            case SHA_1 -> "HmacSHA1";
            case SHA_256 -> "HmacSHA256";
            case SHA_384 -> "HmacSHA384";
            case SHA_512 -> "HmacSHA512";
        };
    }
}
