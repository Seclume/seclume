package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Both curves through the provider, judged by the JDK: a key pair made with
 * the JCA (a test fixture - the production path never makes one), imported
 * into CNG or OpenSSL, a digest signed there and the signature verified by
 * {@code Signature} with the matching hash. A DER a byte out, a wrong curve
 * name or a scalar in the wrong byte order fails the verification.
 */
class EcdsaSignerTest {

    @ParameterizedTest
    @EnumSource(EcdsaSigner.Curve.class)
    void aSignatureTheJdkAccepts(EcdsaSigner.Curve curve) throws Exception {
        Assumptions.assumeTrue(EcdsaSigner.available(), "no off-heap ECDSA on this platform");
        String name = curve == EcdsaSigner.Curve.P384 ? "secp384r1" : "secp256r1";
        String hash = curve == EcdsaSigner.Curve.P384 ? "SHA-384" : "SHA-256";
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(name));
        int field = curve.field();
        for (int round = 0; round < 20; round++) {       // leading zeros and high bits, some of each
            KeyPair pair = generator.generateKeyPair();
            byte[] message = ("round " + round).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] digest = MessageDigest.getInstance(hash).digest(message);
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment point = arena.allocate(curve.pointSize());
                ECPublicKey publicKey = (ECPublicKey) pair.getPublic();
                point.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
                copy(publicKey.getW().getAffineX(), point, 1, field);
                copy(publicKey.getW().getAffineY(), point, 1 + field, field);
                MemorySegment scalar = arena.allocate(field);
                copy(((ECPrivateKey) pair.getPrivate()).getS(), scalar, 0, field);
                MemorySegment hashed = arena.allocateFrom(ValueLayout.JAVA_BYTE, digest);
                MemorySegment der = arena.allocate(curve.maxSignature());
                int length;
                try (EcdsaSigner signer = EcdsaSigner.of(curve, point, scalar)) {
                    assertEquals(curve, signer.curve());
                    length = signer.sign(hashed, der);
                }
                assertTrue(length > 0 && length <= curve.maxSignature(), "length " + length);
                Signature verify = Signature.getInstance(curve == EcdsaSigner.Curve.P384
                        ? "SHA384withECDSA" : "SHA256withECDSA");
                verify.initVerify(pair.getPublic());
                verify.update(message);
                assertTrue(verify.verify(der.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE)),
                        curve + " round " + round + ": the JDK rejects the signature");
            }
        }
    }

    @ParameterizedTest
    @EnumSource(EcdsaSigner.Curve.class)
    void aDigestOfTheOtherLengthIsRefused(EcdsaSigner.Curve curve) throws Exception {
        Assumptions.assumeTrue(EcdsaSigner.available(), "no off-heap ECDSA on this platform");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(
                curve == EcdsaSigner.Curve.P384 ? "secp384r1" : "secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        int field = curve.field();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment point = arena.allocate(curve.pointSize());
            point.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
            copy(((ECPublicKey) pair.getPublic()).getW().getAffineX(), point, 1, field);
            copy(((ECPublicKey) pair.getPublic()).getW().getAffineY(), point, 1 + field, field);
            MemorySegment scalar = arena.allocate(field);
            copy(((ECPrivateKey) pair.getPrivate()).getS(), scalar, 0, field);
            try (EcdsaSigner signer = EcdsaSigner.of(curve, point, scalar)) {
                MemorySegment wrong = arena.allocate(curve == EcdsaSigner.Curve.P384 ? 32 : 48);
                assertThrows(IllegalArgumentException.class,
                        () -> signer.sign(wrong, arena.allocate(curve.maxSignature())));
            }
        }
    }

    @ParameterizedTest
    @EnumSource(EcdsaSigner.Curve.class)
    void theMaximumSignatureFitsShortFormLengths(EcdsaSigner.Curve curve) {
        assertEquals(curve == EcdsaSigner.Curve.P384 ? 104 : 72, curve.maxSignature());
        assertFalse(curve.maxSignature() - 2 > 127, "the SEQUENCE length needs the long form");
    }

    /** Test fixture only: a JCA number into exactly {@code field} bytes. */
    private static void copy(java.math.BigInteger value, MemorySegment into, long at, int field) {
        byte[] bytes = value.toByteArray();
        int from = Math.max(0, bytes.length - field);
        int length = bytes.length - from;
        for (int i = 0; i < field - length; i++) {
            into.set(ValueLayout.JAVA_BYTE, at + i, (byte) 0);
        }
        MemorySegment.copy(bytes, from, into, ValueLayout.JAVA_BYTE, at + field - length, length);
    }
}
