package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * A native key closed is freed, and a use after that is refused before it
 * reaches the native code - which would read freed memory. Closing twice is
 * harmless, and a close lets the next caller in: a lock it kept would hang
 * every later use. Isolated: it counts the keys the process holds.
 */
@Isolated
class ClosedNativeKeyTest {

    @Test
    void aClosedEcdhKeyIsNotUsedAgain() {
        for (NativeEcdh.Group group : new NativeEcdh.Group[] {NativeEcdh.Group.P256,
                NativeEcdh.Group.P384}) {
            try (Arena arena = Arena.ofConfined();
                 NativeEcdh peer = NativeEcdh.generate(group)) {
                MemorySegment point = arena.allocate(group.publicSize());
                peer.publicKey(point);
                NativeEcdh key = NativeEcdh.generate(group);
                MemorySegment secret = arena.allocate(group.secretSize());
                key.derive(point, secret);                       // open: it derives
                key.close();
                key.close();                                     // twice: harmless
                IllegalStateException refused = assertThrows(IllegalStateException.class,
                        () -> key.derive(point, secret), group.toString());
                assertTrue(refused.getMessage().contains("closed"), refused.getMessage());
            }
        }
    }

    @Test
    void aClosedEcdsaSignerIsFreedAndNotUsedAgain() throws Exception {
        Assumptions.assumeTrue(EcdsaSigner.available(), "no off-heap ECDSA on this platform");
        EcdsaSigner.Curve curve = EcdsaSigner.Curve.P256;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        int field = curve.field();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment point = arena.allocate(curve.pointSize());
            point.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
            copy(((ECPublicKey) pair.getPublic()).getW().getAffineX(), point, 1, field);
            copy(((ECPublicKey) pair.getPublic()).getW().getAffineY(), point, 1 + field, field);
            MemorySegment scalar = arena.allocate(field);
            copy(((ECPrivateKey) pair.getPrivate()).getS(), scalar, 0, field);
            MemorySegment digest = arena.allocate(32);
            MemorySegment der = arena.allocate(curve.maxSignature());
            int before = PrivateSigningKey.held();
            EcdsaSigner signer = EcdsaSigner.of(curve, point, scalar);
            assertTrue(signer.sign(digest, der) > 0);
            signer.close();
            signer.close();                                      // twice: harmless
            assertEquals(before, PrivateSigningKey.held(), "the key was not freed");
            assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
                IllegalStateException refused = assertThrows(IllegalStateException.class,
                        () -> signer.sign(digest, der));
                assertTrue(refused.getMessage().contains("closed"), refused.getMessage());
            }, "a use after close hung - the close kept its lock");
        }
    }

    private static void copy(BigInteger value, MemorySegment out, int at, int length) {
        byte[] bytes = value.toByteArray();
        int from = Math.max(0, bytes.length - length);
        int n = bytes.length - from;
        for (int i = 0; i < n; i++) {
            out.set(ValueLayout.JAVA_BYTE, at + length - n + i, bytes[from + i]);
        }
    }
}
