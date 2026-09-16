package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * HKDF and {@code HKDF-Expand-Label}, against values this code did not compute.
 *
 * <p>Every expected value below was produced by <b>OpenSSL 3.5.5</b> on another
 * machine and pasted in. That is the point: a test that compares an
 * implementation with itself proves only that it is deterministic, and a key
 * derivation that is deterministically wrong agrees with no server on earth.
 *
 * <p>The commands are in the comment on each constant, so the numbers can be
 * reproduced rather than believed. Two of them - the RFC 5869 extract and
 * expand - are also the published test vectors of that RFC, so OpenSSL and the
 * standard agree before this code is asked anything.
 *
 * <p>{@code HKDF-Expand-Label} is checked against OpenSSL's own
 * {@code TLS13-KDF}, which builds the label structure itself. That matters more
 * than it looks: the structure is a two-byte length, a one-byte-prefixed label
 * beginning {@code "tls13 "} and a one-byte-prefixed context, and every way of
 * getting that wrong produces bytes that are perfectly random-looking and agree
 * with nothing.
 */
class HkdfTest {

    private static final HexFormat HEX = HexFormat.of();

    /**
     * RFC 5869, test case 1.
     *
     * <pre>openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt mode:EXTRACT_ONLY \
     *   -kdfopt hexsalt:000102030405060708090a0b0c \
     *   -kdfopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b HKDF</pre>
     */
    @Test
    void extractMatchesTheRfcVector() {
        String prk = extract(HashAlgorithm.SHA_256, "000102030405060708090a0b0c",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        assertEquals("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", prk);
    }

    /**
     * The same test case's expansion - 42 bytes, so three blocks and a
     * remainder, which is where a chaining mistake shows.
     *
     * <pre>openssl kdf -keylen 42 -kdfopt digest:SHA2-256 -kdfopt mode:EXPAND_ONLY \
     *   -kdfopt hexkey:0777... -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9 HKDF</pre>
     */
    @Test
    void expandMatchesTheRfcVector() {
        String okm = expand(HashAlgorithm.SHA_256,
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "f0f1f2f3f4f5f6f7f8f9", 42);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865", okm);
    }

    /**
     * A label without a context.
     *
     * <pre>openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt mode:EXPAND_ONLY \
     *   -kdfopt 'prefix:tls13 ' -kdfopt label:derived -kdfopt hexkey:0b*32 TLS13-KDF</pre>
     */
    @Test
    void expandLabelWithoutContext() {
        String out = expandLabel(HashAlgorithm.SHA_256, "0b".repeat(32), "derived", "", 32);
        assertEquals("4b5b595b26474857eda85d80fd627ea49dac749166e893012b8c781b56949f92", out);
    }

    /**
     * And with one - the transcript hash is a context in every real use.
     *
     * <pre>... -kdfopt label:key -kdfopt hexdata:0102030405060708 ...</pre>
     */
    @Test
    void expandLabelWithContext() {
        String out = expandLabel(HashAlgorithm.SHA_256, "0b".repeat(32), "key",
                "0102030405060708", 16);
        assertEquals("07f9141c0e1687471c41d6a77e979be6", out);
    }

    /**
     * SHA-384, because that is what the cipher suite both test servers pick
     * uses: {@code TLS_AES_256_GCM_SHA384}. A key schedule tested only on
     * SHA-256 would pass everywhere and fail against the actual servers.
     *
     * <pre>... -kdfopt digest:SHA2-384 -kdfopt label:'c hs traffic' \
     *   -kdfopt hexdata:aabbccdd -kdfopt hexkey:0b*96 TLS13-KDF</pre>
     */
    @Test
    void expandLabelWithSha384() {
        String out = expandLabel(HashAlgorithm.SHA_384, "0b".repeat(96), "c hs traffic",
                "aabbccdd", 48);
        assertEquals("ead8e33fe367edc5045594f661c64cec7d6d90026e7e3a6b98ae098bb28a0170"
                + "94e9f92c9cbb82ab603e364bb0e82b55", out);
    }

    /** Extract with SHA-384 as well, since the schedule starts with one. */
    @Test
    void extractWithSha384() {
        String prk = extract(HashAlgorithm.SHA_384, "00", "0b".repeat(32));
        assertEquals("e75612a8229b15268f03e4af0a615fc60c5a37e08ccf8cde66aaa26101f4a751"
                + "39749240301108d7b7aded80e701e1c9", prk);
    }

    /** More than 255 blocks cannot be counted in one byte, and it says so. */
    @Test
    void tooMuchOutputIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment prk = of(arena, "0b".repeat(32));
            MemorySegment out = arena.allocate(256 * 32);
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> Hkdf.expand(HashAlgorithm.SHA_256, prk, null, out, 0, 256 * 32));
            org.junit.jupiter.api.Assertions.assertTrue(
                    refused.getMessage().contains("255"), refused.getMessage());
        }
    }

    // ---- the small machinery ---------------------------------------------

    private static String extract(HashAlgorithm algorithm, String saltHex, String ikmHex) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(algorithm.digestLength());
            Hkdf.extract(algorithm, of(arena, saltHex), of(arena, ikmHex), out, 0);
            return hex(out, algorithm.digestLength());
        }
    }

    private static String expand(HashAlgorithm algorithm, String prkHex, String infoHex,
            int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(length);
            Hkdf.expand(algorithm, of(arena, prkHex), of(arena, infoHex), out, 0, length);
            return hex(out, length);
        }
    }

    private static String expandLabel(HashAlgorithm algorithm, String secretHex, String label,
            String contextHex, int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(length);
            Hkdf.expandLabel(algorithm, of(arena, secretHex), label,
                    contextHex.isEmpty() ? null : of(arena, contextHex), out, 0, length);
            return hex(out, length);
        }
    }

    private static MemorySegment of(Arena arena, String hex) {
        byte[] bytes = HEX.parseHex(hex);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static String hex(MemorySegment segment, int length) {
        byte[] bytes = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
        return HEX.formatHex(bytes);
    }
}
