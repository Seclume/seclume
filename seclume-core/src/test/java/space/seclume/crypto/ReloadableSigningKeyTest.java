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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.Checkpoint;

/**
 * A private key in OpenSSL's or CNG's memory is in a CRaC or SnapStart image
 * of the process. One that can be read again from its source is freed before
 * the checkpoint and read again on first use after the restore; the keys
 * that cannot be are counted, so that the checkpoint can be refused.
 */
@Isolated
@Timeout(120)
class ReloadableSigningKeyTest {

    @BeforeEach
    void aBackend() {
        Assumptions.assumeTrue(PrivateSigningKey.available(), "neither OpenSSL 3 nor CNG here");
    }

    /** A P-256 key's PKCS#8 - made by the JDK, which is fine for a test's key. */
    private static byte[] pkcs8() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair().getPrivate().getEncoded();
    }

    /** Decodes {@code der} each time, counting how often; fails while {@code failing}. */
    private static Supplier<PrivateSigningKey> source(byte[] der, AtomicInteger reads,
                                                      AtomicBoolean failing) {
        return () -> {
            if (failing.get()) {
                throw new IllegalStateException("the key's source is not there");
            }
            reads.incrementAndGet();
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment encoded = arena.allocate(der.length);
                MemorySegment.copy(der, 0, encoded, ValueLayout.JAVA_BYTE, 0, der.length);
                return PrivateSigningKey.decode(encoded, der.length);
            }
        };
    }

    private static byte[] sign(PrivateSigningKey key, byte[] message) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(message.length);
            MemorySegment.copy(message, 0, data, ValueLayout.JAVA_BYTE, 0, message.length);
            MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
            int n = key.sign("SHA256", false, data, message.length, out);
            return out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    private static boolean verifies(byte[] publicKey, byte[] message, byte[] signature)
            throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(publicKey)));
        verifier.update(message);
        return verifier.verify(signature);
    }

    @Test
    void aCheckpointFreesTheKeyAndTheNextSignatureReadsItAgain() throws Exception {
        AtomicInteger reads = new AtomicInteger();
        int before = PrivateSigningKey.held();
        byte[] message = "the message".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        try (PrivateSigningKey key = PrivateSigningKey.reloadable(
                source(pkcs8(), reads, new AtomicBoolean()), "the test's key")) {
            byte[] publicKey = key.publicKey();
            assertEquals(before + 1, PrivateSigningKey.held());
            assertTrue(verifies(publicKey, message, sign(key, message)));

            Checkpoint.wipeAll();
            assertEquals(before, PrivateSigningKey.held(), "the key would be in the image");
            assertFalse(((ReloadableSigningKey) key).loaded());
            assertArrayEquals(publicKey, key.publicKey(), "the public half needs no key");
            assertEquals(1, reads.get());

            assertTrue(verifies(publicKey, message, sign(key, message)),
                    "after the restore it signs as the same key");
            assertTrue(key.is("EC"));
            assertEquals(2, reads.get());
            assertEquals(before + 1, PrivateSigningKey.held());

            Checkpoint.wipeAll();
            Checkpoint.wipeAll();
            assertTrue(verifies(publicKey, message, sign(key, message)));
            assertEquals(3, reads.get(), "dropped twice, read once");
        }
        assertEquals(before, PrivateSigningKey.held(), "closed, and still held");
    }

    @Test
    void anotherKeyAtTheSourceAfterTheRestoreIsRefused() throws Exception {
        byte[] first = pkcs8();
        byte[] second = pkcs8();
        AtomicInteger reads = new AtomicInteger();
        int before = PrivateSigningKey.held();
        Supplier<PrivateSigningKey> one = source(first, new AtomicInteger(), new AtomicBoolean());
        Supplier<PrivateSigningKey> other = source(second, new AtomicInteger(), new AtomicBoolean());
        try (PrivateSigningKey key = PrivateSigningKey.reloadable(
                () -> reads.getAndIncrement() == 0 ? one.get() : other.get(), "the test's key")) {
            ((ReloadableSigningKey) key).drop();
            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> sign(key, new byte[] {1}));
            assertTrue(refused.getMessage().contains("the test's key is another key"),
                    refused.getMessage());
            assertEquals(before, PrivateSigningKey.held(), "the other key was left open");
        }
    }

    @Test
    void aSourceThatFailsAfterTheRestoreFailsThatSignatureOnly() throws Exception {
        AtomicBoolean failing = new AtomicBoolean();
        AtomicInteger reads = new AtomicInteger();
        try (PrivateSigningKey key = PrivateSigningKey.reloadable(
                source(pkcs8(), reads, failing), "the test's key")) {
            ((ReloadableSigningKey) key).drop();
            failing.set(true);
            assertThrows(IllegalStateException.class, () -> sign(key, new byte[] {1}));
            failing.set(false);
            assertTrue(sign(key, new byte[] {1}).length > 0, "the next one read it again");
        }
    }

    @Test
    void aClosedKeyStaysClosed() throws Exception {
        PrivateSigningKey key = PrivateSigningKey.reloadable(
                source(pkcs8(), new AtomicInteger(), new AtomicBoolean()), "the test's key");
        key.close();
        ((ReloadableSigningKey) key).drop();
        assertThrows(IllegalStateException.class, () -> sign(key, new byte[] {1}));
        key.close();
    }

    @Test
    void aKeyWithoutASourceIsCountedWithWhoMadeIt() throws Exception {
        int before = PrivateSigningKey.held();
        int namedBefore = PrivateSigningKey.heldBy().size();
        try (PrivateSigningKey generated = PrivateSigningKey.generateP256()) {
            Checkpoint.wipeAll();
            assertEquals(before + 1, PrivateSigningKey.held(), "a generated key cannot be read "
                    + "again - it stays, and is counted");
            // Who made it: the first class outside this package - here, as the
            // test lives in it, the test framework's.
            assertEquals(namedBefore + 1, PrivateSigningKey.heldBy().size());
            assertTrue(PrivateSigningKey.heldBy().stream()
                    .noneMatch(by -> by.startsWith("space.seclume.crypto.")),
                    PrivateSigningKey.heldBy().toString());
            assertTrue(generated.publicKey().length > 0);
        }
        assertEquals(before, PrivateSigningKey.held());
    }

    /**
     * Signatures while the key is dropped again and again: each gets a key,
     * none a freed one. The key is dropped directly - not through
     * Checkpoint.wipeAll, which would wipe what tests running beside this one
     * hold - a bounded number of times.
     */
    @Test
    void signaturesWhileTheKeyIsDroppedAllGetAKey() throws Exception {
        byte[] der = pkcs8();
        try (PrivateSigningKey key = PrivateSigningKey.reloadable(
                source(der, new AtomicInteger(), new AtomicBoolean()), "the test's key")) {
            byte[] publicKey = key.publicKey();
            List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());
            AtomicBoolean stop = new AtomicBoolean();
            Thread dropper = Thread.ofPlatform().start(() -> {
                for (int i = 0; i < 50 && !stop.get(); i++) {
                    ((ReloadableSigningKey) key).drop();
                    try {
                        Thread.sleep(2);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            });
            List<Thread> signers = new ArrayList<>();
            try {
                for (int t = 0; t < 4; t++) {
                    signers.add(Thread.ofPlatform().start(() -> {
                        try {
                            for (int i = 0; i < 50; i++) {
                                byte[] message = {(byte) i};
                                assertTrue(verifies(publicKey, message, sign(key, message)));
                            }
                        } catch (Throwable e) {
                            failures.add(e);
                        }
                    }));
                }
                for (Thread signer : signers) {
                    signer.join();
                }
            } finally {
                stop.set(true);
                dropper.join();
            }
            assertEquals(List.of(), failures);
        }
    }
}
