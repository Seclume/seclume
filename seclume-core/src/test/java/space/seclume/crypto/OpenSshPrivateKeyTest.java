package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * OpenSSH private key parsing, bound checks and format validation.
 */
class OpenSshPrivateKeyTest {

    private static final String BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String END = "-----END OPENSSH PRIVATE KEY-----";

    @Test
    void isRecognizesOpenSshHeader() {
        try (Arena arena = Arena.ofConfined()) {
            byte[] valid = (BEGIN + "\n...\n" + END).getBytes(StandardCharsets.US_ASCII);
            MemorySegment key = arena.allocate(valid.length);
            MemorySegment.copy(valid, 0, key, ValueLayout.JAVA_BYTE, 0, valid.length);
            assertTrue(OpenSshPrivateKey.is(key, valid.length));

            byte[] invalid = "-----BEGIN RSA PRIVATE KEY-----".getBytes(StandardCharsets.US_ASCII);
            MemorySegment notKey = arena.allocate(invalid.length);
            MemorySegment.copy(invalid, 0, notKey, ValueLayout.JAVA_BYTE, 0, invalid.length);
            assertFalse(OpenSshPrivateKey.is(notKey, invalid.length));
        }
    }

    @Test
    void manipulatedLengthThrowsIllegalArgumentExceptionNotIndexOutOfBounds() throws IOException {
        // Construct OpenSSH binary payload:
        // magic (15 bytes: "openssh-key-v1\0")
        // cipher: "none"
        // kdf: "none"
        // kdf options: empty
        // num keys: 1
        // pubkey: manipulated length that is <= total length, but > remaining length (length - at)
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.write("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII));
        writeString(out, "none");
        writeString(out, "none");
        writeString(out, "");
        out.writeInt(1);

        // At this point, we have written 15 + 8 + 8 + 4 + 4 = 39 bytes.
        // We write a pubkey length of 20, but only provide 5 trailing bytes.
        // Total payload length will be 39 + 4 + 5 = 48 bytes.
        // The value 20 is <= total length (48), but remaining bytes are only 5.
        // Old code checked value > length (20 > 48 -> false), leading to IndexOutOfBoundsException.
        // New code checks value > length - at (20 > 5 -> true) and throws IllegalArgumentException.
        out.writeInt(20);
        out.write(new byte[] {1, 2, 3, 4, 5});
        out.flush();

        byte[] payload = bytes.toByteArray();
        String pem = BEGIN + "\n" + Base64.getEncoder().encodeToString(payload) + "\n" + END;
        byte[] raw = pem.getBytes(StandardCharsets.US_ASCII);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(raw.length);
            MemorySegment.copy(raw, 0, key, ValueLayout.JAVA_BYTE, 0, raw.length);
            MemorySegment derOut = arena.allocate(OpenSshPrivateKey.maxDerLength(raw.length));

            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> OpenSshPrivateKey.toDer(key, raw.length, derOut));
            assertEquals("a length in the OpenSSH key is out of range", e.getMessage());
        }
    }

    @Test
    void manipulatedSectionLengthThrowsIllegalArgumentException() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.write("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII));
        writeString(out, "none");
        writeString(out, "none");
        writeString(out, "");
        out.writeInt(1);
        writeString(out, "dummy-pubkey");

        // Now reading sectionLength:
        // We write sectionLength = 100, but only append 10 bytes.
        out.writeInt(100);
        out.write(new byte[10]);
        out.flush();

        byte[] payload = bytes.toByteArray();
        String pem = BEGIN + "\n" + Base64.getEncoder().encodeToString(payload) + "\n" + END;
        byte[] raw = pem.getBytes(StandardCharsets.US_ASCII);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(raw.length);
            MemorySegment.copy(raw, 0, key, ValueLayout.JAVA_BYTE, 0, raw.length);
            MemorySegment derOut = arena.allocate(OpenSshPrivateKey.maxDerLength(raw.length));

            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> OpenSshPrivateKey.toDer(key, raw.length, derOut));
            assertEquals("a length in the OpenSSH key is out of range", e.getMessage());
        }
    }

    private static void writeString(DataOutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.US_ASCII);
        out.writeInt(b.length);
        out.write(b);
    }
}
