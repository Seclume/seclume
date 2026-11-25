package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.DiffieHellman;
import space.seclume.secret.SecretScope;

/**
 * Native network encryption's Diffie-Hellman group is the server's to choose,
 * and the client's exponent was as long as the prime: a 65535-byte prime was
 * years of CPU in connect, before any login. Groups of 1024 to 4096 bits are
 * taken, and the exponent is 256 bits whatever the group.
 */
class DhGroupTest {

    @Test
    void aDhGroupOutsideTheBoundsIsRefused() throws IOException {
        assertThrows(IOException.class, () -> AdvancedNegotiation.checkGroup(127, 127));
        assertThrows(IOException.class, () -> AdvancedNegotiation.checkGroup(513, 513));
        assertThrows(IOException.class, () -> AdvancedNegotiation.checkGroup(65535, 65535));
        assertThrows(IOException.class, () -> AdvancedNegotiation.checkGroup(256, 255),
                "a public value that is not the group's length");
        assertEquals(128, AdvancedNegotiation.checkGroup(128, 128));
        assertEquals(512, AdvancedNegotiation.checkGroup(512, 512));
    }

    @Test
    @Timeout(20)
    void theExponentIs256Bits() throws Exception {
        byte[] prime = BigInteger.probablePrime(4096, new SecureRandom()).toByteArray();
        byte[] exact = new byte[512];
        System.arraycopy(prime, prime.length - 512, exact, 0, 512);
        try (DiffieHellman dh = AdvancedNegotiation.keyPair(MemorySegment.ofArray(exact),
                MemorySegment.ofArray(new byte[] {2}))) {
            Field exponent = DiffieHellman.class.getDeclaredField("exponent");
            exponent.setAccessible(true);
            assertEquals(32, ((SecretScope) exponent.get(dh)).length());
            MemorySegment own = MemorySegment.ofArray(new byte[512]);
            long began = System.nanoTime();
            dh.publicValue(own, 0);
            assertTrue(System.nanoTime() - began < 10_000_000_000L);
        }
    }
}
