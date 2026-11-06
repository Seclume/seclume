package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * An OpenSSH Ed25519 key file built field by field: check values that differ
 * in only one of their four bytes, a string that ends exactly at the end of
 * its section and one a byte longer, a length with its top bit set, and the
 * seed it yields. Written against the mutants PIT left alive in this package.
 */
class OpenSshKeyEdgesTest {

    private static final byte[] SEED = new byte[32];
    private static final byte[] PUBLIC = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            SEED[i] = (byte) (0xa0 + i);
            PUBLIC[i] = (byte) (0x10 + i);
        }
    }

    private static void string(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }

    private static void string(DataOutputStream out, String value) throws IOException {
        string(out, value.getBytes(StandardCharsets.US_ASCII));
    }

    /** The private section; {@code commentLength} lets a test lie about the comment's length. */
    private static byte[] section(int check1, int check2, int commentLength, byte[] comment, int padding)
            throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeInt(check1);
        out.writeInt(check2);
        string(out, "ssh-ed25519");
        string(out, PUBLIC);
        out.writeInt(64);
        out.write(SEED);
        out.write(PUBLIC);
        if (commentLength < 0) {
            return bytes.toByteArray();           // the section ends with the private key
        }
        out.writeInt(commentLength);
        out.write(comment);
        for (int i = 1; i <= padding; i++) {
            out.write(i);
        }
        return bytes.toByteArray();
    }

    private static byte[] file(byte[] section, int sectionLength) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.write("openssh-key-v1".getBytes(StandardCharsets.US_ASCII));
        out.write(0);
        string(out, "none");
        string(out, "none");
        string(out, new byte[0]);
        out.writeInt(1);
        ByteArrayOutputStream key = new ByteArrayOutputStream();
        DataOutputStream keyOut = new DataOutputStream(key);
        string(keyOut, "ssh-ed25519");
        string(keyOut, PUBLIC);
        string(out, key.toByteArray());
        out.writeInt(sectionLength);
        out.write(section);
        String pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(70, new byte[] {'\n'}).encodeToString(bytes.toByteArray())
                + "\n-----END OPENSSH PRIVATE KEY-----\n";
        return pem.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] file(byte[] section) throws IOException {
        return file(section, section.length);
    }

    private static byte[] der(byte[] file) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, file);
            MemorySegment out = arena.allocate(OpenSshPrivateKey.maxDerLength(file.length));
            int length = OpenSshPrivateKey.toDer(key, file.length, out);
            return out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    private static String refusal(byte[] file) {
        return assertThrows(IllegalArgumentException.class, () -> der(file)).getMessage();
    }

    @Test
    void anEd25519KeyIsItsSeedInPkcs8() throws IOException {
        byte[] comment = "me@host".getBytes(StandardCharsets.US_ASCII);
        byte[] der = der(file(section(0x01020304, 0x01020304, comment.length, comment, 3)));
        assertEquals(48, der.length);
        assertArrayEquals(SEED, Arrays.copyOfRange(der, 16, 48));
        assertEquals(0x30, der[0]);
        assertEquals(OpenSshPrivateKey.maxDerLength(100), 356, "the bound is the file's length and 256");
    }

    @Test
    void checkValuesThatDifferInAnyOneByteDiffer() throws IOException {
        int base = 0x5a5a5a5a;
        for (int shift = 0; shift < 32; shift += 8) {
            for (int bit : new int[] {0x01, 0x80}) {
                int other = base ^ (bit << shift);
                String message = refusal(file(section(base, other, 0, new byte[0], 0)));
                assertEquals("the OpenSSH key's check values differ - a passphrase-protected key, or a damaged one",
                        message, "bit " + Integer.toHexString(bit << shift));
            }
        }
        for (int zeroAgainst : new int[] {0x01000000, 0x00010000, 0x00000100, 0x80000000}) {
            assertEquals("the OpenSSH key's check values differ - a passphrase-protected key, or a damaged one",
                    refusal(file(section(0, zeroAgainst, 0, new byte[0], 0))), Integer.toHexString(zeroAgainst));
        }
        der(file(section(0xffffffff, 0xffffffff, 0, new byte[0], 0)));
        der(file(section(0x80000001, 0x80000001, 0, new byte[0], 0)));
    }

    @Test
    void aStringMayEndExactlyAtTheEndOfItsSectionAndNotOneByteLater() throws IOException {
        byte[] last = section(7, 7, -1, null, 0);
        assertArrayEquals(SEED, Arrays.copyOfRange(der(file(last)), 16, 48),
                "the 64 bytes of the private key are the last of the section");
        byte[] short1 = Arrays.copyOf(last, last.length - 1);
        assertEquals("a length in the OpenSSH key is out of range", refusal(file(short1)),
                "64 bytes said, 63 there");
        byte[] negative = last.clone();
        int lengthAt = last.length - 64 - 4;
        negative[lengthAt] = (byte) 0x80;
        assertEquals("a length in the OpenSSH key is out of range", refusal(file(negative)),
                "a length with its top bit set");
    }

    @Test
    void theSectionLengthIsCheckedAgainstWhatIsLeft() throws IOException {
        byte[] section = section(9, 9, 0, new byte[0], 0);
        assertEquals("a length in the OpenSSH key is out of range", refusal(file(section, section.length + 1)));
        assertEquals("a length in the OpenSSH key is out of range", refusal(file(section, -1)));
        assertEquals("the OpenSSH key ends too early",
                refusal(file(Arrays.copyOf(section, 7), 7)), "not even two check values");
    }
}
