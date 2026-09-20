package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretScope;

/**
 * Signing with a key that is not a Java object, judged by one that is.
 *
 * <p>The key pair is made by the JCA, which is the only way to get a public
 * key an independent verifier will accept. Then the private half is handed to
 * {@link P256Signer} as raw bytes in native memory, the JCA copy is dropped,
 * and every signature is checked with {@code Signature.verify} against the
 * public key. So the thing being tested is not "does our code agree with
 * itself" but "does a verifier that never saw this code accept what it
 * produced" - including the DER encoding, which is where a hand-rolled
 * signature usually goes wrong and where it goes wrong silently.
 *
 * <p>The heap is irrelevant on the test's side and the JCA is used freely
 * here. What matters is that the production path from {@code MemorySegment} to
 * signature exists and is correct; that it stays off the heap is
 * {@code ForbiddenApiTest} and the heap dump harness.
 */
class P256SignerTest {

    private static final byte[] MESSAGE =
            "TLS 1.3, client CertificateVerify".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void onlyWhereThereIsAProvider() {
        Assumptions.assumeTrue(P256Signer.available(),
                "off-heap P-256 signing needs Windows or 64-bit Linux with libcrypto.so.3");
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return generator.generateKeyPair();
    }

    /** {@code 0x04 || x || y}, each coordinate padded to 32 bytes. */
    private static byte[] uncompressed(ECPublicKey key) {
        ECPoint w = key.getW();
        byte[] point = new byte[65];
        point[0] = 4;
        copyFixed(w.getAffineX(), point, 1);
        copyFixed(w.getAffineY(), point, 33);
        return point;
    }

    private static byte[] scalar(ECPrivateKey key) {
        byte[] d = new byte[32];
        copyFixed(key.getS(), d, 0);
        return d;
    }

    /** Big-endian into exactly 32 bytes - BigInteger adds a sign byte or drops zeroes. */
    private static void copyFixed(BigInteger value, byte[] into, int at) {
        byte[] bytes = value.toByteArray();
        int from = Math.max(0, bytes.length - 32);
        int length = bytes.length - from;
        System.arraycopy(bytes, from, into, at + 32 - length, length);
    }

    private static byte[] digestOf(byte[] message) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(message);
    }

    /** Signs with the off-heap signer and hands back the DER bytes. */
    private static byte[] sign(byte[] point, byte[] d, byte[] digest) {
        try (Arena arena = Arena.ofConfined();
             SecretScope key = SecretScope.in(arena, 32)) {
            MemorySegment publicPoint = arena.allocate(65);
            MemorySegment.copy(point, 0, publicPoint, ValueLayout.JAVA_BYTE, 0, 65);
            MemorySegment.copy(d, 0, key.segment(), ValueLayout.JAVA_BYTE, 0, 32);
            key.length(32);

            MemorySegment hash = arena.allocate(32);
            MemorySegment.copy(digest, 0, hash, ValueLayout.JAVA_BYTE, 0, 32);
            MemorySegment der = arena.allocate(P256Signer.MAX_SIGNATURE);

            int length;
            try (P256Signer signer = P256Signer.of(publicPoint, key.segment())) {
                length = signer.sign(hash, der);
            }
            byte[] signature = new byte[length];
            MemorySegment.copy(der, ValueLayout.JAVA_BYTE, 0, signature, 0, length);
            return signature;
        }
    }

    private static boolean verifies(ECPublicKey key, byte[] digestedMessage, byte[] signature)
            throws Exception {
        // NONEwithECDSA takes the digest, which is what the signer was given -
        // SHA256withECDSA would hash a second time and compare nothing useful.
        Signature verifier = Signature.getInstance("NONEwithECDSA");
        verifier.initVerify(key);
        verifier.update(digestedMessage);
        return verifier.verify(signature);
    }

    @Test
    void theJcaAcceptsWhatTheOffHeapSignerProduced() throws Exception {
        KeyPair pair = keyPair();
        byte[] digest = digestOf(MESSAGE);

        byte[] signature = sign(uncompressed((ECPublicKey) pair.getPublic()),
                scalar((ECPrivateKey) pair.getPrivate()), digest);

        assertTrue(verifies((ECPublicKey) pair.getPublic(), digest, signature),
                "an independent verifier rejected the signature");
    }

    /**
     * Many keys, not one.
     *
     * <p>The DER encoding depends on the values: an {@code r} whose top bit is
     * set needs a leading zero, one with leading zero bytes must lose them.
     * A single key pair exercises one of those shapes by chance, and the test
     * that runs on the other shape is the one somebody else's stack runs.
     */
    @Test
    void itHoldsForFortyDifferentKeys() throws Exception {
        for (int round = 0; round < 40; round++) {
            KeyPair pair = keyPair();
            byte[] digest = digestOf(("round " + round).getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII));

            byte[] signature = sign(uncompressed((ECPublicKey) pair.getPublic()),
                    scalar((ECPrivateKey) pair.getPrivate()), digest);

            assertTrue(verifies((ECPublicKey) pair.getPublic(), digest, signature),
                    "round " + round);
            assertEquals(0x30, signature[0] & 0xff, "not a DER SEQUENCE in round " + round);
            assertEquals(signature.length - 2, signature[1] & 0xff,
                    "the DER length does not match in round " + round);
        }
    }

    /** A signature over a different digest must not verify - the negative control. */
    @Test
    void anotherDigestDoesNotVerify() throws Exception {
        KeyPair pair = keyPair();
        byte[] signature = sign(uncompressed((ECPublicKey) pair.getPublic()),
                scalar((ECPrivateKey) pair.getPrivate()), digestOf(MESSAGE));

        assertFalse(verifies((ECPublicKey) pair.getPublic(),
                digestOf("something else entirely".getBytes(
                        java.nio.charset.StandardCharsets.US_ASCII)), signature));
    }

    /**
     * A key that does not belong to the certificate is refused at import.
     *
     * <p>The alternative is a handshake that fails at {@code CertificateVerify}
     * with an alert from the server, which tells an operator far less than
     * "this key does not match this certificate" does.
     */
    @Test
    void aMismatchedPairIsRefused() throws Exception {
        KeyPair one = keyPair();
        KeyPair other = keyPair();

        assertThrows(RuntimeException.class, () -> sign(
                uncompressed((ECPublicKey) one.getPublic()),
                scalar((ECPrivateKey) other.getPrivate()),
                new byte[32]));
    }

    @Test
    void aClosedSignerRefusesToSign() throws Exception {
        KeyPair pair = keyPair();
        byte[] point = uncompressed((ECPublicKey) pair.getPublic());
        byte[] d = scalar((ECPrivateKey) pair.getPrivate());

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment publicPoint = arena.allocate(65);
            MemorySegment.copy(point, 0, publicPoint, ValueLayout.JAVA_BYTE, 0, 65);
            MemorySegment key = arena.allocate(32);
            MemorySegment.copy(d, 0, key, ValueLayout.JAVA_BYTE, 0, 32);

            P256Signer signer = P256Signer.of(publicPoint, key);
            signer.close();
            signer.close(); // twice is allowed

            MemorySegment der = arena.allocate(P256Signer.MAX_SIGNATURE);
            MemorySegment hash = arena.allocate(32);
            assertThrows(IllegalStateException.class, () -> signer.sign(hash, der));
        }
    }

    /** The DER encoder on its own, including both awkward shapes. */
    @Test
    void theEncoderPadsAndTrimsCorrectly() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment raw = arena.allocate(64);
            MemorySegment out = arena.allocate(P256Signer.MAX_SIGNATURE);

            // r with the top bit set: needs a leading zero.
            // s with leading zeroes: they have to go.
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            r[0] = (byte) 0x80;
            r[31] = 1;
            s[30] = 2;
            s[31] = 3;
            MemorySegment.copy(r, 0, raw, ValueLayout.JAVA_BYTE, 0, 32);
            MemorySegment.copy(s, 0, raw, ValueLayout.JAVA_BYTE, 32, 32);

            int length = P256Signer.der(raw, out);
            byte[] der = new byte[length];
            MemorySegment.copy(out, ValueLayout.JAVA_BYTE, 0, der, 0, length);

            // 30 46 02 21 00 80..01 02 02 02 03
            assertEquals(0x30, der[0] & 0xff);
            assertEquals(length - 2, der[1] & 0xff);
            assertEquals(0x02, der[2] & 0xff);
            assertEquals(33, der[3] & 0xff, "r needed a leading zero");
            assertEquals(0x00, der[4] & 0xff);
            assertEquals(0x02, der[4 + 33] & 0xff);
            assertEquals(2, der[5 + 33] & 0xff, "s should have been trimmed to two bytes");
            assertEquals(2, der[6 + 33] & 0xff);
            assertEquals(3, der[7 + 33] & 0xff);
            assertEquals(2 + 2 + 33 + 2 + 2, length);
        }
    }

    /** An all-zero half still encodes as a single zero byte, not as nothing. */
    @Test
    void aZeroIntegerKeepsOneByte() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment raw = arena.allocate(64);
            MemorySegment out = arena.allocate(P256Signer.MAX_SIGNATURE);
            int length = P256Signer.der(raw, out);

            assertEquals(8, length);
            assertEquals(1, out.get(ValueLayout.JAVA_BYTE, 3), "r has to keep one zero byte");
            assertEquals(0, out.get(ValueLayout.JAVA_BYTE, 4));
            assertEquals(1, out.get(ValueLayout.JAVA_BYTE, 6));
            assertEquals(0, out.get(ValueLayout.JAVA_BYTE, 7));
        }
    }
}
