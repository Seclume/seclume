package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.crypto.Wycheproof.Result;
import space.seclume.crypto.Wycheproof.Vector;

/**
 * seclume's own cryptography against Project Wycheproof.
 *
 * <p>The other tests in this package check the primitives against the RFC
 * vectors and against the JDK. Both are written with the same idea of what
 * could go wrong as the code itself. Wycheproof's cases come from the other
 * direction: each one is a bug that was found in some library - a tag
 * compared too loosely, an output length past HKDF's limit, a peer point that
 * is not on the curve (the invalid-curve attack that leaks the private key).
 *
 * <p>Covered is everything whose logic seclume owns: AES-GCM in Java (every
 * key size) and behind {@link AesGcmCipher} (OpenSSL or CNG, as the platform
 * gives), HMAC, HKDF and PBKDF2 over SHA-1/256/384/512, and the P-256 key
 * agreement, where the point parsing and the glue around the provider are
 * ours. Signature verification is not here: the TLS handshake leaves it to
 * the JDK ({@code HandshakeSignature}), and the JDK has its own Wycheproof runs.
 *
 * <p>What a primitive's API cannot even express is left out, and counted:
 * {@link #coverage()} fails when a file changes or a filter starts dropping
 * more than it should, so a skip can never grow silently.
 */
class WycheproofTest {

    // ---------------------------------------------------------------- AES-GCM

    /** seclume's AES-GCM takes a 12-byte nonce and a 16-byte tag - what TLS 1.3 uses. */
    static Stream<Vector> aesGcmVectors() {
        return Wycheproof.load("aes_gcm_test.json").stream()
                .filter(v -> v.number("ivSize") == 96 && v.number("tagSize") == 128);
    }

    /** {@link AesGcmCipher#of} takes 16- and 32-byte keys; 24 is not a TLS 1.3 key. */
    static Stream<Vector> aesGcmNativeVectors() {
        return aesGcmVectors().filter(v -> v.number("keySize") != 192);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("aesGcmVectors")
    void aesGcmJava(Vector v) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = v.segment(arena, "key");
            try (AesGcmCipher cipher = new JavaAesGcm(key, 0, (int) key.byteSize())) {
                checkAesGcm(v, arena, cipher);
            }
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("aesGcmNativeVectors")
    void aesGcmPlatform(Vector v) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = v.segment(arena, "key");
            try (AesGcmCipher cipher = AesGcmCipher.of(key, 0, (int) key.byteSize())) {
                assumeTrue(!"java".equals(cipher.implementation()),
                        "no native AES-GCM on this platform - the Java one is tested above");
                checkAesGcm(v, arena, cipher);
            }
        }
    }

    private static void checkAesGcm(Vector v, Arena arena, AesGcmCipher cipher) {
        MemorySegment nonce = v.segment(arena, "iv");
        MemorySegment aad = v.segment(arena, "aad");
        byte[] msg = v.bytes("msg");
        byte[] ct = v.bytes("ct");
        byte[] tag = v.bytes("tag");
        byte[] sealed = concat(ct, tag);

        if (v.result() == Result.VALID) {
            MemorySegment in = segment(arena, msg);
            MemorySegment out = arena.allocate(msg.length + AesGcm.TAG);
            cipher.encrypt(nonce, 0, aad, 0, aad.byteSize(), in, 0, msg.length, out, 0);
            assertArrayEquals(sealed, bytes(out), v + ": ciphertext and tag");
        }

        MemorySegment in = segment(arena, sealed);
        MemorySegment out = arena.allocate(Math.max(ct.length, 1)).asSlice(0, ct.length);
        boolean opened = cipher.decrypt(nonce, 0, aad, 0, aad.byteSize(), in, 0, ct.length, out, 0);
        if (v.result() == Result.INVALID) {
            assertFalse(opened, v + ": a forged or altered message was accepted");
            assertArrayEquals(new byte[ct.length], bytes(out),
                    v + ": plaintext was handed out although the tag did not match");
        } else {
            assertTrue(opened, v + ": a genuine message was rejected");
            assertArrayEquals(msg, bytes(out), v + ": plaintext");
        }
    }

    // ------------------------------------------------------------------- HMAC

    static Stream<Vector> hmacVectors() {
        return Stream.of("hmac_sha1_test.json", "hmac_sha256_test.json",
                        "hmac_sha384_test.json", "hmac_sha512_test.json")
                .flatMap(file -> Wycheproof.load(file).stream());
    }

    /**
     * Wycheproof also has truncated tags. seclume always produces the whole
     * MAC; the vector's tag is compared with as many leading bytes as it has,
     * which is exactly how a truncating caller would use it.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("hmacVectors")
    void hmac(Vector v) {
        HashAlgorithm algorithm = hash(v.file());
        try (Arena arena = Arena.ofConfined();
                Hmac hmac = new Hmac(algorithm, v.segment(arena, "key"))) {
            hmac.update(v.segment(arena, "msg"));
            MemorySegment mac = arena.allocate(hmac.macLength());
            hmac.doFinal(mac, 0);

            byte[] tag = v.bytes("tag");
            assertEquals(v.number("tagSize") / 8, tag.length, v + ": tag length");
            byte[] ours = Arrays.copyOf(bytes(mac), tag.length);
            if (v.result() == Result.INVALID) {
                assertFalse(Arrays.equals(tag, ours), v + ": an altered tag matched");
            } else {
                assertArrayEquals(tag, ours, v + ": MAC");
            }
        }
    }

    // ------------------------------------------------------------------- HKDF

    static Stream<Vector> hkdfVectors() {
        return Stream.of("hkdf_sha1_test.json", "hkdf_sha256_test.json",
                        "hkdf_sha384_test.json", "hkdf_sha512_test.json")
                .flatMap(file -> Wycheproof.load(file).stream());
    }

    /**
     * Extract, then Expand to the requested length. The invalid cases ask for
     * one byte more than 255 blocks, which must be refused rather than
     * wrapping the one-byte block counter around.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("hkdfVectors")
    void hkdf(Vector v) {
        HashAlgorithm algorithm = hash(v.file());
        int size = (int) v.number("size");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment prk = arena.allocate(algorithm.digestLength());
            Hkdf.extract(algorithm, v.segment(arena, "salt"), v.segment(arena, "ikm"), prk, 0);
            MemorySegment okm = arena.allocate(Math.max(size, 1)).asSlice(0, size);
            MemorySegment info = v.segment(arena, "info");

            if (v.result() == Result.INVALID) {
                assertThrows(IllegalArgumentException.class,
                        () -> Hkdf.expand(algorithm, prk, info, okm, 0, size),
                        v + ": an output length HKDF cannot produce was accepted");
                return;
            }
            Hkdf.expand(algorithm, prk, info, okm, 0, size);
            assertArrayEquals(v.bytes("okm"), bytes(okm), v + ": output key material");
        }
    }

    // ----------------------------------------------------------------- PBKDF2

    /**
     * One vector runs 16,777,216 iterations - minutes of SHA-1 in Java for no
     * code path the others do not reach. Everything up to a million runs.
     */
    static final long PBKDF2_ITERATION_LIMIT = 1_000_000;

    static Stream<Vector> pbkdf2Vectors() {
        return Stream.of("pbkdf2_hmacsha1_test.json", "pbkdf2_hmacsha256_test.json",
                        "pbkdf2_hmacsha384_test.json", "pbkdf2_hmacsha512_test.json")
                .flatMap(file -> Wycheproof.load(file).stream())
                .filter(v -> v.number("iterationCount") <= PBKDF2_ITERATION_LIMIT);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("pbkdf2Vectors")
    void pbkdf2(Vector v) {
        HashAlgorithm algorithm = hash(v.file());
        int length = (int) v.number("dkLen");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(Math.max(length, 1)).asSlice(0, length);
            Pbkdf2.derive(algorithm, v.segment(arena, "password"), v.segment(arena, "salt"),
                    (int) v.number("iterationCount"), out);
            assertEquals(Result.VALID, v.result(), v + ": the file has no invalid PBKDF2 cases");
            assertArrayEquals(v.bytes("dk"), bytes(out), v + ": derived key");
        }
    }

    // ------------------------------------------------------------- P-256 ECDH

    static Stream<Vector> ecdhP256Vectors() {
        return Wycheproof.load("ecdh_secp256r1_ecpoint_test.json").stream();
    }

    /**
     * The peer's point is what arrives in the server's key share. Points off
     * the curve, on its twist, compressed or truncated must all be refused
     * before any arithmetic, and a refusal must leave the output untouched.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("ecdhP256Vectors")
    void ecdhP256(Vector v) {
        BigInteger d = new BigInteger(1, v.bytes("private"));
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scalar = segment(arena, P256.fixed(d));
            MemorySegment own = segment(arena, P256.encode(P256.multiply(d, P256.G)));
            byte[] peerBytes = v.bytes("public");
            // NativeP256 checks the length itself; a native segment of the
            // wrong size is exactly what a malformed key share would give it.
            MemorySegment peer = arena.allocate(Math.max(peerBytes.length, 1))
                    .asSlice(0, peerBytes.length);
            MemorySegment.copy(peerBytes, 0, peer, ValueLayout.JAVA_BYTE, 0, peerBytes.length);
            MemorySegment out = arena.allocate(NativeP256.SECRET_SIZE).fill((byte) 0x5a);

            try (NativeP256 key = NativeP256.importKey(own, scalar)) {
                boolean derived;
                try {
                    key.derive(peer, out);
                    derived = true;
                } catch (RuntimeException rejected) {
                    derived = false;
                }
                switch (v.result()) {
                    case VALID -> {
                        assertTrue(derived, v + ": a valid peer point was rejected");
                        assertArrayEquals(v.bytes("shared"), bytes(out), v + ": shared secret");
                    }
                    case INVALID -> {
                        assertFalse(derived, v + ": an invalid peer point was accepted");
                        byte[] untouched = new byte[NativeP256.SECRET_SIZE];
                        Arrays.fill(untouched, (byte) 0x5a);
                        assertArrayEquals(untouched, bytes(out),
                                v + ": output written although the point was refused");
                    }
                    case ACCEPTABLE -> {
                        if (derived) {
                            assertArrayEquals(v.bytes("shared"), bytes(out), v + ": shared secret");
                        }
                    }
                }
            } finally {
                out.fill((byte) 0);
                scalar.fill((byte) 0);
            }
        }
    }

    // --------------------------------------------------------------- coverage

    /**
     * How many cases each source yields, fixed. If Wycheproof's files are
     * updated, or a filter above starts dropping more, this says so - instead
     * of the suite quietly testing less. The numbers are what the files at the
     * commit in {@code wycheproof/README.md} give.
     */
    @Test
    void coverage() {
        assertEquals(316, Wycheproof.load("aes_gcm_test.json").size());
        assertEquals(197, aesGcmVectors().count(), "AES-GCM with a 96-bit nonce and 128-bit tag");
        assertEquals(133, aesGcmNativeVectors().count(), "AES-GCM with a 128- or 256-bit key");
        assertCounts(hmacVectors().toList(), "HMAC");
        assertCounts(hkdfVectors().toList(), "HKDF");
        assertCounts(pbkdf2Vectors().toList(), "PBKDF2");
        assertEquals(1, Stream.of("pbkdf2_hmacsha1_test.json", "pbkdf2_hmacsha256_test.json",
                        "pbkdf2_hmacsha384_test.json", "pbkdf2_hmacsha512_test.json")
                .flatMap(file -> Wycheproof.load(file).stream())
                .filter(v -> v.number("iterationCount") > PBKDF2_ITERATION_LIMIT).count(),
                "PBKDF2 cases left out for their iteration count");
        assertEquals(355, ecdhP256Vectors().count(), "P-256 ECDH");
        assertEquals(24, ecdhP256Vectors().filter(v -> v.result() == Result.INVALID).count(),
                "P-256 ECDH cases that must be refused");
    }

    private static void assertCounts(List<Vector> vectors, String what) {
        long expected = switch (what) {
            case "HMAC" -> 170 + 174 + 174 + 174;
            case "HKDF" -> 87 + 86 + 83 + 83;
            case "PBKDF2" -> 64 - 1 + 60 + 58 + 58;
            default -> throw new IllegalArgumentException(what);
        };
        if (vectors.size() != expected) {
            fail(what + ": expected " + expected + " vectors, found " + vectors.size());
        }
    }

    // ---------------------------------------------------------------- helpers

    private static HashAlgorithm hash(String file) {
        if (file.contains("sha1")) {
            return HashAlgorithm.SHA_1;
        } else if (file.contains("sha256")) {
            return HashAlgorithm.SHA_256;
        } else if (file.contains("sha384")) {
            return HashAlgorithm.SHA_384;
        } else if (file.contains("sha512")) {
            return HashAlgorithm.SHA_512;
        }
        throw new IllegalArgumentException("no hash in " + file);
    }

    private static MemorySegment segment(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1)).asSlice(0, bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static byte[] bytes(MemorySegment segment) {
        return segment.toArray(ValueLayout.JAVA_BYTE);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * Just enough P-256 to turn Wycheproof's private scalar into the public
     * point {@link NativeP256#importKey} wants next to it. Affine, variable
     * time, test-only: the scalars are published test data.
     */
    static final class P256 {

        static final BigInteger P = new BigInteger(
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
        static final BigInteger A = P.subtract(BigInteger.valueOf(3));
        static final BigInteger[] G = {
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        };

        private P256() {
        }

        static BigInteger[] multiply(BigInteger k, BigInteger[] point) {
            BigInteger[] result = null;
            for (int i = k.bitLength() - 1; i >= 0; i--) {
                result = add(result, result);
                if (k.testBit(i)) {
                    result = add(result, point);
                }
            }
            return result;
        }

        /** Point addition with {@code null} as the point at infinity. */
        static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
            if (p == null) {
                return q;
            }
            if (q == null) {
                return p;
            }
            BigInteger lambda;
            if (p[0].equals(q[0])) {
                if (!p[1].equals(q[1]) || p[1].signum() == 0) {
                    return null;
                }
                lambda = p[0].pow(2).multiply(BigInteger.valueOf(3)).add(A)
                        .multiply(p[1].shiftLeft(1).modInverse(P)).mod(P);
            } else {
                lambda = q[1].subtract(p[1]).multiply(q[0].subtract(p[0]).modInverse(P)).mod(P);
            }
            BigInteger x = lambda.pow(2).subtract(p[0]).subtract(q[0]).mod(P);
            BigInteger y = lambda.multiply(p[0].subtract(x)).subtract(p[1]).mod(P);
            return new BigInteger[] {x, y};
        }

        static byte[] encode(BigInteger[] point) {
            byte[] out = new byte[65];
            out[0] = 4;
            System.arraycopy(fixed(point[0]), 0, out, 1, 32);
            System.arraycopy(fixed(point[1]), 0, out, 33, 32);
            return out;
        }

        /** 32 bytes big-endian, whatever leading zeroes BigInteger adds or drops. */
        static byte[] fixed(BigInteger value) {
            byte[] raw = value.toByteArray();
            byte[] out = new byte[32];
            int length = Math.min(raw.length, 32);
            System.arraycopy(raw, raw.length - length, out, 32 - length, length);
            return out;
        }
    }
}
