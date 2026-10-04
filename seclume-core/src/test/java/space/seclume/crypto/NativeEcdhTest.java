package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;

import javax.crypto.KeyAgreement;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Each group against the JDK's key agreement, both ways: the native key with
 * the JDK's public key, the JDK's key with the native public key - the same
 * secret, in TLS's encoding of both.
 */
class NativeEcdhTest {

    @ParameterizedTest
    @EnumSource(NativeEcdh.Group.class)
    void agreesWithTheJdk(NativeEcdh.Group group) throws Exception {
        KeyPair jdk = jdkPair(group);
        try (Arena arena = Arena.ofConfined();
                NativeEcdh key = NativeEcdh.generate(group)) {
            MemorySegment ours = arena.allocate(group.publicSize());
            key.publicKey(ours);

            MemorySegment theirs = arena.allocate(group.publicSize());
            MemorySegment.copy(MemorySegment.ofArray(encode(group, jdk.getPublic())), 0, theirs, 0,
                    group.publicSize());
            MemorySegment secret = arena.allocate(group.secretSize());
            key.derive(theirs, secret);

            KeyAgreement agreement = KeyAgreement.getInstance(
                    group == NativeEcdh.Group.X25519 ? "XDH" : "ECDH");
            agreement.init(jdk.getPrivate());
            agreement.doPhase(decode(group, ours.toArray(ValueLayout.JAVA_BYTE)), true);
            byte[] expected = agreement.generateSecret();
            assertEquals(group.secretSize(), expected.length);
            assertArrayEquals(expected, secret.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @ParameterizedTest
    @EnumSource(value = NativeEcdh.Group.class, names = {"P256", "P384"})
    void aPointOffTheCurveIsRefused(NativeEcdh.Group group) {
        try (Arena arena = Arena.ofConfined();
                NativeEcdh key = NativeEcdh.generate(group)) {
            MemorySegment bad = arena.allocate(group.publicSize());
            bad.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
            bad.set(ValueLayout.JAVA_BYTE, group.publicSize() - 1, (byte) 1);
            assertThrows(RuntimeException.class,
                    () -> key.derive(bad, arena.allocate(group.secretSize())));
        }
    }

    @ParameterizedTest
    @EnumSource(value = NativeEcdh.Group.class, names = "X25519")
    void aLowOrderX25519KeyIsRefused(NativeEcdh.Group group) {
        try (Arena arena = Arena.ofConfined();
                NativeEcdh key = NativeEcdh.generate(group)) {
            MemorySegment zero = arena.allocate(32);           // u = 0: order 1
            assertThrows(RuntimeException.class, () -> key.derive(zero, arena.allocate(32)));
        }
    }

    private static KeyPair jdkPair(NativeEcdh.Group group) throws Exception {
        if (group == NativeEcdh.Group.X25519) {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve(group)));
        return generator.generateKeyPair();
    }

    private static String curve(NativeEcdh.Group group) {
        return group == NativeEcdh.Group.P256 ? "secp256r1" : "secp384r1";
    }

    /** A JDK public key in TLS's encoding. */
    private static byte[] encode(NativeEcdh.Group group, PublicKey key) {
        if (key instanceof XECPublicKey xec) {
            byte[] big = xec.getU().toByteArray();
            byte[] little = new byte[32];
            for (int i = 0; i < Math.min(32, big.length); i++) {
                little[i] = big[big.length - 1 - i];
            }
            return little;
        }
        ECPoint point = ((ECPublicKey) key).getW();
        int size = (group.publicSize() - 1) / 2;
        byte[] out = new byte[group.publicSize()];
        out[0] = 4;
        fixed(point.getAffineX(), out, 1, size);
        fixed(point.getAffineY(), out, 1 + size, size);
        return out;
    }

    /** TLS's encoding back to a JDK public key. */
    private static PublicKey decode(NativeEcdh.Group group, byte[] encoded) throws Exception {
        if (group == NativeEcdh.Group.X25519) {
            byte[] big = new byte[33];
            for (int i = 0; i < 32; i++) {
                big[32 - i] = encoded[i];
            }
            return KeyFactory.getInstance("X25519").generatePublic(
                    new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(big)));
        }
        int size = (group.publicSize() - 1) / 2;
        BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 1, 1 + size));
        BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 1 + size,
                1 + 2 * size));
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curve(group)));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y),
                parameters.getParameterSpec(ECParameterSpec.class)));
    }

    private static void fixed(BigInteger value, byte[] out, int at, int size) {
        byte[] bytes = value.toByteArray();
        int skip = bytes.length > size ? bytes.length - size : 0;
        System.arraycopy(bytes, skip, out, at + size - (bytes.length - skip), bytes.length - skip);
    }
}
