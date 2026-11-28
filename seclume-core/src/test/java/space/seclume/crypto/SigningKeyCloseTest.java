package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.CountDownLatch;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * close() freed the native key while another thread was signing with it: a
 * use after free - a crash of the JVM, or a heap corrupted in silence. A
 * close now waits for a signature under way, and a closed key signs nothing.
 */
@Timeout(120)
class SigningKeyCloseTest {

    @Test
    void closingWhileAnotherThreadSignsIsSafe() throws Exception {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG to sign with");
        closeUnderASigner(PrivateSigningKey::generateP256);
    }

    /**
     * The CNG key itself, on Windows: generateP256 takes OpenSSL wherever it
     * is there, so the CNG key's close was untried on a machine with both.
     */
    @Test
    @org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.WINDOWS)
    void closingACngKeyWhileAnotherThreadSignsIsSafe() throws Exception {
        assumeTrue(CngSigningKey.available(), "no CNG");
        closeUnderASigner(() -> {
            PrivateSigningKey key = SigningKeys.p256(CngSigningKey::decode);
            org.junit.jupiter.api.Assertions.assertInstanceOf(CngSigningKey.class, key);
            return key;
        });
        PrivateSigningKey key = SigningKeys.p256(CngSigningKey::decode);
        key.close();
        try (Arena arena = Arena.ofConfined()) {
            assertThrows(IllegalStateException.class, () -> key.sign("SHA256", false,
                    arena.allocate(64), 64, arena.allocate(256)));
        }
    }

    private static void closeUnderASigner(java.util.function.Supplier<PrivateSigningKey> make)
            throws Exception {
        for (int round = 0; round < 2000; round++) {
            PrivateSigningKey key = make.get();
            CountDownLatch signing = new CountDownLatch(1);
            Thread signer = Thread.ofPlatform().start(() -> {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment message = arena.allocate(64);
                    MemorySegment signature = arena.allocate(256);
                    signing.countDown();
                    for (int i = 0; i < 50; i++) {
                        key.sign("SHA256", false, message, 64, signature);
                    }
                } catch (IllegalStateException closedUnderIt) {
                    // the close came first - what a closed key is to answer
                }
            });
            signing.await();
            key.close();
            signer.join();
        }
        // Reached at all: the JVM is alive after 2,000 closes under a signer.
    }

    @Test
    void aClosedKeySignsNothing() {
        assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG to sign with");
        PrivateSigningKey key = PrivateSigningKey.generateP256();
        key.close();
        try (Arena arena = Arena.ofConfined()) {
            assertThrows(IllegalStateException.class, () -> key.sign("SHA256", false,
                    arena.allocate(64), 64, arena.allocate(256)));
        }
    }
}
