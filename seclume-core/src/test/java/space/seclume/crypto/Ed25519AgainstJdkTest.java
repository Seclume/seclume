package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.SplittableRandom;

import org.junit.jupiter.api.Test;

/**
 * seclume's Ed25519 against the JDK's, key by key and message by message:
 * the same signature byte for byte (Ed25519 is deterministic, and the
 * signature hashes the public key, so this checks that too), and the JDK
 * accepting it under seclume's public key - for seeds and messages drawn at
 * random, including seeds of all zero and all one bits and empty and long
 * messages. A carry left out of the field arithmetic shows on some inputs and
 * not others; three hundred of them find what a known-answer vector or two
 * would not. Written against the mutants PIT left alive in this package.
 */
class Ed25519AgainstJdkTest {

    private static PrivateKey jdkKey(byte[] seed) throws Exception {
        return KeyFactory.getInstance("Ed25519").generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519,
                seed));
    }

    private static PublicKey publicFromRaw(byte[] raw) throws Exception {
        byte[] prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
        byte[] x509 = new byte[prefix.length + 32];
        System.arraycopy(prefix, 0, x509, 0, prefix.length);
        System.arraycopy(raw, 0, x509, prefix.length, 32);
        return KeyFactory.getInstance("Ed25519").generatePublic(new java.security.spec.X509EncodedKeySpec(x509));
    }

    @Test
    void threeHundredKeysAndMessagesSignAsTheJdkSigns() throws Exception {
        SplittableRandom random = new SplittableRandom(25519);
        for (int round = 0; round < 300; round++) {
            byte[] seed = new byte[32];
            if (round == 0) {
                Arrays.fill(seed, (byte) 0);
            } else if (round == 1) {
                Arrays.fill(seed, (byte) 0xff);
            } else {
                random.nextBytes(seed);
            }
            byte[] message = new byte[round == 2 ? 0 : round == 3 ? 4096 : random.nextInt(200)];
            random.nextBytes(message);
            PrivateKey key = jdkKey(seed);
            Signature jdk = Signature.getInstance("Ed25519");
            jdk.initSign(key);
            jdk.update(message);
            byte[] expected = jdk.sign();
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment seedSegment = arena.allocateFrom(ValueLayout.JAVA_BYTE, seed);
                MemorySegment messageSegment = arena.allocate(Math.max(1, message.length));
                MemorySegment.copy(message, 0, messageSegment, ValueLayout.JAVA_BYTE, 0, message.length);
                MemorySegment signature = arena.allocate(Ed25519.SIGNATURE_LENGTH + 3);
                Ed25519.sign(seedSegment, 0, 32, messageSegment, 0, message.length, signature, 3);
                byte[] ours = signature.asSlice(3, 64).toArray(ValueLayout.JAVA_BYTE);
                assertArrayEquals(expected, ours, "round " + round);
                MemorySegment publicKey = arena.allocate(32);
                Ed25519.publicKey(seedSegment, 0, 32, publicKey, 0);
                byte[] raw = publicKey.toArray(ValueLayout.JAVA_BYTE);
                Signature verify = Signature.getInstance("Ed25519");
                verify.initVerify(publicFromRaw(raw));
                verify.update(message);
                assertTrue(verify.verify(ours), "the JDK verifies round " + round + " with seclume's public key");
            }
        }
    }
}
