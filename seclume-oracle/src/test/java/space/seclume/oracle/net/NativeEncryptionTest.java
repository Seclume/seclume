package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.secret.SecretScope;

/**
 * The packet layer of native encryption without a server: the layout of a
 * sealed packet, and what opening one refuses. That the server takes what is
 * sealed here, and that its checksums pass, is shown against Oracle itself -
 * LocalOracleNneTest.
 */
class NativeEncryptionTest {

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 15, 16, 17, 100})
    void encryptionAloneRoundTripsAndPadsToWholeBlocks(int length) throws IOException {
        try (Arena arena = Arena.ofConfined(); SecretScope shared = secret(64);
             NativeEncryption sender = new NativeEncryption(NativeEncryption.AES256, 0, shared,
                     arena.allocate(16));
             NativeEncryption receiver = new NativeEncryption(NativeEncryption.AES256, 0, shared,
                     arena.allocate(16))) {
            MemorySegment data = arena.allocate(Math.max(1, length));
            for (int i = 0; i < length; i++) {
                data.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 7 + 3));
            }
            MemorySegment packet = arena.allocate(length + sender.overhead());
            int sealed = sender.seal(data, 0, length, packet, 0);
            int blocks = (length + 15) / 16;
            assertEquals(blocks * 16 + 2, sealed, "whole blocks, the padding byte, the folding key");
            assertEquals(0, packet.get(ValueLayout.JAVA_BYTE, sealed - 1));
            if (length > 0) {
                assertFalse(packet.asSlice(0, length).mismatch(data.asSlice(0, length)) == -1,
                        "the data went out in the clear");
            }
            int opened = receiver.open(packet, 0, sealed);
            assertEquals(length, opened);
            assertEquals(-1, packet.asSlice(0, length).mismatch(data.asSlice(0, length)));
        }
    }

    @Test
    void aBadPaddingByteIsRefused() {
        try (Arena arena = Arena.ofConfined(); SecretScope shared = secret(64);
             NativeEncryption layer = new NativeEncryption(NativeEncryption.AES128, 0, shared,
                     arena.allocate(16))) {
            MemorySegment packet = arena.allocate(18);
            packet.set(ValueLayout.JAVA_BYTE, 16, (byte) 17);   // more padding than a block
            IOException refused = assertThrows(IOException.class, () -> layer.open(packet, 0, 18));
            assertTrue(refused.getMessage().contains("padding"), refused.getMessage());
            MemorySegment ragged = arena.allocate(20);
            assertThrows(IOException.class, () -> layer.open(ragged, 0, 20));
        }
    }

    @Test
    void onlyAesAndSha2AreTaken() {
        try (Arena arena = Arena.ofConfined(); SecretScope shared = secret(64)) {
            assertThrows(IllegalArgumentException.class,
                    () -> new NativeEncryption(6, 0, shared, arena.allocate(16)));      // RC4_256
            assertThrows(IllegalArgumentException.class,
                    () -> new NativeEncryption(NativeEncryption.AES256, 3, shared,
                            arena.allocate(16)));                                       // SHA1
        }
    }

    @Test
    void theModeFromTheUrl() {
        assertEquals(AdvancedNegotiation.Mode.ACCEPTED, AdvancedNegotiation.Mode.of(null));
        assertEquals(AdvancedNegotiation.Mode.OFF, AdvancedNegotiation.Mode.of("off"));
        assertEquals(AdvancedNegotiation.Mode.REQUESTED, AdvancedNegotiation.Mode.of("Requested"));
        assertEquals(AdvancedNegotiation.Mode.REQUIRED, AdvancedNegotiation.Mode.of("required"));
        assertThrows(IllegalArgumentException.class, () -> AdvancedNegotiation.Mode.of("always"));
        assertFalse(AdvancedNegotiation.Mode.ACCEPTED.offered());
        assertTrue(AdvancedNegotiation.Mode.REQUIRED.offered());
    }

    @Test
    void theAcceptFlagsThatAskForTheNegotiation() {
        assertTrue(AdvancedNegotiation.wanted(0x59, 0x00));     // a listener that requires it
        assertTrue(AdvancedNegotiation.wanted(0x51, 0x01));     // offered and taken up
        assertFalse(AdvancedNegotiation.wanted(0x49, 0x0a));    // an ordinary listener
    }

    private static SecretScope secret(int length) {
        SecretScope scope = SecretScope.allocateShared(length);
        for (int i = 0; i < length; i++) {
            scope.segment().set(ValueLayout.JAVA_BYTE, i, (byte) (i * 13 + 1));
        }
        scope.length(length);
        return scope;
    }
}
