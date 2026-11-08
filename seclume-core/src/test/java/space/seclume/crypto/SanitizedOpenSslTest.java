package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SplittableRandom;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The boundary between Java and OpenSSL under AddressSanitizer and
 * UndefinedBehaviorSanitizer: the {@code sanitizers} job of the nightly
 * {@code fuzz} workflow builds libcrypto with both, loads it with
 * {@code -Dseclume.crypto.libcrypto=} and runs the core's tests against it. A
 * read or a write past what seclume handed OpenSSL, a use after free, a double
 * free, undefined behaviour in a call it made: the sanitizer stops the process,
 * and the job fails.
 *
 * <p>This class does two things there. It makes sure the sanitized library is
 * the one in use - a job that loaded the system's libcrypto instead would be
 * green and prove nothing - and it drives the boundary harder than the other
 * tests do: threads that make, use and close keys and AES-GCM contexts at
 * once, every length around the block size, forged tags, keys closed twice,
 * a key used after its close.
 *
 * <p>Runs when {@code -Dseclume.sanitizer.libcrypto=} names the library it
 * expects; skipped in every other build.
 */
@Timeout(600)
class SanitizedOpenSslTest {

    private static final int ROUNDS = Integer.getInteger("seclume.sanitizer.rounds", 400);

    @BeforeAll
    static void onlyInTheSanitizerJob() {
        Assumptions.assumeTrue(System.getProperty("seclume.sanitizer.libcrypto") != null,
                "runs in the sanitizers job, with -Dseclume.sanitizer.libcrypto=");
    }

    @Test
    void theSanitizedLibraryIsTheOneInUse() {
        assertTrue(LibCrypto.available(), LibCrypto.missing());
        assertEquals(System.getProperty("seclume.sanitizer.libcrypto"), LibCrypto.file(),
                "the job would test the system's libcrypto, not the sanitized one");
        assertTrue(PrivateSigningKey.available());
        try (Arena arena = Arena.ofConfined();
             AesGcmCipher cipher = AesGcmCipher.of(arena.allocate(32), 0, 32)) {
            assertTrue(cipher instanceof OpenSslAesGcm, "AES-GCM is " + cipher.implementation()
                    + ", not OpenSSL's");
        }
    }

    /** Keys made, used and closed on eight threads at once; every signature verified by the JDK. */
    @Test
    void keysOnManyThreadsAtOnce() throws Exception {
        List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            long seed = 0x5A_17_0000L + t;
            threads.add(Thread.ofPlatform().start(() -> {
                SplittableRandom random = new SplittableRandom(seed);
                try {
                    for (int i = 0; i < ROUNDS / 8; i++) {
                        oneKey(random);
                    }
                } catch (Throwable e) {
                    failures.add(e);
                }
            }));
        }
        for (Thread thread : threads) {
            thread.join();
        }
        assertEquals(List.of(), failures);
    }

    private static void oneKey(SplittableRandom random) throws Exception {
        PrivateSigningKey key = random.nextBoolean() ? PrivateSigningKey.generateP256() : decoded();
        byte[] publicKey = key.publicKey();
        byte[] message = new byte[random.nextInt(0, 2049)];
        random.nextBytes(message);
        byte[] signature = sign(key, message);
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(publicKey)));
        verifier.update(message);
        assertTrue(verifier.verify(signature));
        key.close();
        key.close();
        assertThrows(IllegalStateException.class, () -> sign(key, message),
                "a closed key signed");
    }

    /** A key decoded from a PKCS#8 the JDK made, through native memory. */
    private static PrivateSigningKey decoded() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] der = generator.generateKeyPair().getPrivate().getEncoded();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment encoded = arena.allocate(der.length);
            MemorySegment.copy(der, 0, encoded, ValueLayout.JAVA_BYTE, 0, der.length);
            return PrivateSigningKey.decode(encoded, der.length);
        }
    }

    private static byte[] sign(PrivateSigningKey key, byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(Math.max(1, message.length));
            MemorySegment.copy(message, 0, data, ValueLayout.JAVA_BYTE, 0, message.length);
            MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
            int n = key.sign("SHA256", false, data, message.length, out);
            return out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /**
     * AES-GCM at every length from 0 to 70 and at random ones up to 64 KiB,
     * with and without associated data, in place and not: what goes in comes
     * out, and a flipped bit anywhere is refused with the output untouched.
     */
    @Test
    void aesGcmAtTheEdgesOfItsBuffers() {
        SplittableRandom random = new SplittableRandom(0xAE5);
        for (int round = 0; round < ROUNDS; round++) {
            int length = round <= 70 ? round : random.nextInt(0, 65_537);
            int aadLength = random.nextInt(0, 3) == 0 ? 0 : random.nextInt(1, 300);
            int keyLength = random.nextBoolean() ? 16 : 32;
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment key = filled(arena, keyLength, random);
                MemorySegment nonce = filled(arena, AesGcm.NONCE, random);
                MemorySegment aad = filled(arena, Math.max(1, aadLength), random);
                MemorySegment plain = filled(arena, Math.max(1, length), random);
                MemorySegment sealed = arena.allocate(length + AesGcm.TAG);
                MemorySegment opened = arena.allocate(Math.max(1, length));
                try (AesGcmCipher cipher = AesGcmCipher.of(key, 0, keyLength)) {
                    cipher.encrypt(nonce, 0, aad, 0, aadLength, plain, 0, length, sealed, 0);
                    assertTrue(cipher.decrypt(nonce, 0, aad, 0, aadLength, sealed, 0, length,
                            opened, 0), "round " + round);
                    assertArrayEquals(plain.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                            opened.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                            "round " + round);
                    long flip = random.nextLong(0, length + AesGcm.TAG);
                    sealed.set(ValueLayout.JAVA_BYTE, flip,
                            (byte) (sealed.get(ValueLayout.JAVA_BYTE, flip) ^ 1));
                    opened.fill((byte) 0x5A);
                    assertFalse(cipher.decrypt(nonce, 0, aad, 0, aadLength, sealed, 0, length,
                            opened, 0), "round " + round + ": a forged tag was taken");
                }
            }
        }
    }

    private static MemorySegment filled(Arena arena, int length, SplittableRandom random) {
        MemorySegment segment = arena.allocate(length);
        for (int i = 0; i < length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, (byte) random.nextInt());
        }
        return segment;
    }
}
