package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

/**
 * DER read element by element at its bounds, EC private keys in PKCS#8, SEC1
 * and PEM against the JDK's own keys, Shamir's bounds of shares and
 * x-coordinates, and the Java AES-GCM against the JDK's past 255 counter
 * blocks. Written against the mutants PIT left alive in this package.
 */
class CryptoFormatEdgesTest {

    private static MemorySegment of(Arena arena, int... values) {
        MemorySegment segment = arena.allocate(Math.max(1, values.length));
        for (int i = 0; i < values.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, (byte) values[i]);
        }
        return segment;
    }

    private static MemorySegment of(Arena arena, byte[] bytes) {
        return arena.allocateFrom(ValueLayout.JAVA_BYTE, bytes);
    }

    // ------------------------------------------------------------ DER

    @Test
    void aBitStringOfOnlyItsUnusedBitsCountIsEmpty() {
        try (Arena arena = Arena.ofConfined()) {
            Der.Reader empty = new Der.Reader(of(arena, 0x03, 0x01, 0x00), 0, 3).readBitString();
            assertFalse(empty.hasMore(), "nothing after the count");
            Der.Reader one = new Der.Reader(of(arena, 0x03, 0x03, 0x00, 0x05, 0x00), 0, 5).readBitString();
            assertTrue(one.hasMore());
            assertEquals(0x05, one.peekTag());
            one.skipElement();
            assertFalse(one.hasMore(), "exactly the element after the count");
            assertEquals("empty BIT STRING", assertThrows(IllegalArgumentException.class,
                    () -> new Der.Reader(of(arena, 0x03, 0x00), 0, 2).readBitString()).getMessage());
        }
    }

    @Test
    void aSmallIntegerIsOneToFourBytesBigEndian() {
        try (Arena arena = Arena.ofConfined()) {
            assertEquals(0, new Der.Reader(of(arena, 0x02, 0x01, 0x00), 0, 3).readSmallInteger());
            assertEquals(258, new Der.Reader(of(arena, 0x02, 0x02, 0x01, 0x02), 0, 4).readSmallInteger());
            assertEquals(0x01020304,
                    new Der.Reader(of(arena, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04), 0, 6).readSmallInteger());
            assertEquals("expected a small DER INTEGER, found 5 bytes", assertThrows(IllegalArgumentException.class,
                    () -> new Der.Reader(of(arena, 0x02, 0x05, 1, 2, 3, 4, 5), 0, 7).readSmallInteger()).getMessage());
            assertEquals("expected a small DER INTEGER, found 0 bytes", assertThrows(IllegalArgumentException.class,
                    () -> new Der.Reader(of(arena, 0x02, 0x00), 0, 2).readSmallInteger()).getMessage());
        }
    }

    @Test
    void anElementMayEndExactlyAtItsContainersEnd() {
        try (Arena arena = Arena.ofConfined()) {
            // Two elements in a container of 5 bytes, with a byte after the container that is not its own.
            MemorySegment data = of(arena, 0x04, 0x01, 0xaa, 0x05, 0x00, 0x04);
            Der.Reader reader = new Der.Reader(data, 0, 5);
            Der.Range whole = reader.readWhole();
            assertEquals(new Der.Range(0, 3), whole);
            reader.skipElement();
            assertFalse(reader.hasMore());
            assertEquals("truncated DER structure",
                    assertThrows(IllegalArgumentException.class, reader::peekTag).getMessage(),
                    "the byte after the container is not read");
            Der.Reader over = new Der.Reader(of(arena, 0x04, 0x02, 0xaa), 0, 3);
            assertEquals("DER element exceeds its container",
                    assertThrows(IllegalArgumentException.class, over::skipElement).getMessage());
            Der.Reader overTagged = new Der.Reader(of(arena, 0x04, 0x02, 0xaa, 0xbb), 0, 3);
            assertEquals("DER element exceeds its container",
                    assertThrows(IllegalArgumentException.class, overTagged::readOctetStringRange).getMessage());
            assertEquals(new Der.Range(2, 2), new Der.Reader(of(arena, 0x04, 0x02, 0xaa, 0xbb), 0, 4)
                    .readOctetStringRange());
        }
    }

    @Test
    void aLongLengthTakesOneToFourBytes() {
        try (Arena arena = Arena.ofConfined()) {
            byte[] content = new byte[130];
            for (int count = 1; count <= 4; count++) {
                byte[] der = new byte[2 + count + content.length];
                der[0] = 0x04;
                der[1] = (byte) (0x80 | count);
                der[1 + count] = (byte) 130;
                MemorySegment segment = of(arena, der);
                assertEquals(new Der.Range(2 + count, 130),
                        new Der.Reader(segment, 0, der.length).readOctetStringRange(), count + " length bytes");
            }
            for (int count : new int[] {0, 5}) {
                MemorySegment segment = of(arena, 0x04, 0x80 | count, 0, 0, 0, 0, 1, 0);
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> new Der.Reader(segment, 0, 8).readOctetStringRange());
                assertEquals("unsupported DER length of " + count + " bytes", e.getMessage());
            }
            assertEquals("truncated DER structure", assertThrows(IllegalArgumentException.class,
                    () -> new Der.Reader(of(arena, 0x04, 0x82, 0x01), 0, 3).readOctetStringRange()).getMessage());
        }
    }

    // ------------------------------------------------------------ EC private keys

    private static ECPrivateKey ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return (ECPrivateKey) generator.generateKeyPair().getPrivate();
    }

    private static byte[] scalarOf(ECPrivateKey key, int size) {
        byte[] s = key.getS().toByteArray();
        byte[] out = new byte[size];
        int from = Math.max(0, s.length - size);
        System.arraycopy(s, from, out, size - (s.length - from), s.length - from);
        return out;
    }

    @Test
    void pkcs8KeysOfBothCurvesAndTheirPemAreTheJdksScalar() throws Exception {
        for (String[] curve : new String[][] {{"secp256r1", "32"}, {"secp384r1", "48"}}) {
            ECPrivateKey key = ec(curve[0]);
            int size = Integer.parseInt(curve[1]);
            byte[] der = key.getEncoded();
            String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'})
                    .encodeToString(der) + "\n-----END PRIVATE KEY-----\n";
            try (Arena arena = Arena.ofConfined()) {
                for (MemorySegment source : new MemorySegment[] {of(arena, der),
                        of(arena, pem.getBytes(StandardCharsets.US_ASCII))}) {
                    MemorySegment out = arena.allocate(size);
                    assertEquals(size, EcPrivateKeyFile.scalar(source, (int) source.byteSize(), out, size),
                            "the scalar's size is returned");
                    assertArrayEquals(scalarOf(key, size), out.toArray(ValueLayout.JAVA_BYTE), curve[0]);
                }
            }
        }
    }

    @Test
    void aShortSec1ScalarIsPaddedAndTheTargetMayBeExactlyItsSize() {
        byte[] scalar = new byte[31];
        Arrays.fill(scalar, (byte) 0x5a);
        byte[] der = new byte[2 + 3 + 2 + 31];
        int at = 0;
        der[at++] = 0x30;
        der[at++] = (byte) (3 + 2 + 31);
        der[at++] = 0x02;
        der[at++] = 0x01;
        der[at++] = 0x01;
        der[at++] = 0x04;
        der[at++] = 31;
        System.arraycopy(scalar, 0, der, at, 31);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(32);
            out.fill((byte) 0x77);
            assertEquals(32, EcPrivateKeyFile.scalar(of(arena, der), der.length, out, 32));
            byte[] expected = new byte[32];
            System.arraycopy(scalar, 0, expected, 1, 31);
            assertArrayEquals(expected, out.toArray(ValueLayout.JAVA_BYTE), "a leading zero, not the old byte");
            IllegalArgumentException small = assertThrows(IllegalArgumentException.class,
                    () -> EcPrivateKeyFile.scalar(of(arena, der), der.length, arena.allocate(31), 32));
            assertEquals("the private key needs 32 bytes", small.getMessage());
            IllegalArgumentException curve = assertThrows(IllegalArgumentException.class,
                    () -> EcPrivateKeyFile.scalar(of(arena, der), der.length, arena.allocate(64), 64));
            assertEquals("a P-256 or P-384 scalar is 32 or 48 bytes, not 64", curve.getMessage());
        }
    }

    @Test
    void aBeginLineWithoutABodyIsNoKey() {
        try (Arena arena = Arena.ofConfined()) {
            for (String text : new String[] {"-----BEGIN EC PRIVATE KEY-----",
                    "-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----\n"}) {
                byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
                MemorySegment exact = of(arena, bytes);
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> EcPrivateKeyFile.scalar(exact, bytes.length, arena.allocate(32), 32), text);
                assertTrue(e.getMessage().startsWith("this does not look like a PEM private key"), e.getMessage());
            }
            IllegalArgumentException none = assertThrows(IllegalArgumentException.class,
                    () -> EcPrivateKeyFile.scalar(arena.allocate(1), 0, arena.allocate(32), 32));
            assertTrue(none.getMessage().startsWith("this does not look like a PEM private key"), none.getMessage());
        }
    }

    // ------------------------------------------------------------ Shamir

    @Test
    void sharesAreFromTheThresholdTo255AndXFromOneTo255() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, 0x42, 0x17);
            for (int[] split : new int[][] {{2, 2}, {3, 3}, {2, Shamir.MAX_SHARES}}) {
                MemorySegment[] out = new MemorySegment[split[1]];
                for (int i = 0; i < out.length; i++) {
                    out[i] = arena.allocate(2);
                }
                assertDoesNotThrow(() -> Shamir.split(secret, 0, 2, split[0], split[1], out, 0),
                        split[0] + " of " + split[1]);
                int[] xs = new int[split[0]];
                MemorySegment[] ys = new MemorySegment[split[0]];
                for (int i = 0; i < split[0]; i++) {
                    xs[i] = split[1] - i;                     // the last shares: x up to 255
                    ys[i] = out[split[1] - i - 1];
                }
                MemorySegment back = arena.allocate(2);
                Shamir.combine(xs, ys, 0, 2, back, 0);
                assertArrayEquals(new byte[] {0x42, 0x17}, back.toArray(ValueLayout.JAVA_BYTE));
            }
            MemorySegment[] many = new MemorySegment[256];
            Arrays.fill(many, arena.allocate(2));
            assertEquals("between the threshold (2) and 255 shares, not 256", assertThrows(
                    IllegalArgumentException.class, () -> Shamir.split(secret, 0, 2, 2, 256, many, 0)).getMessage());
            assertEquals("between the threshold (3) and 255 shares, not 2", assertThrows(
                    IllegalArgumentException.class, () -> Shamir.split(secret, 0, 2, 3, 2, many, 0)).getMessage());
            assertEquals("a threshold of 1 is no sharing at all - at least 2", assertThrows(
                    IllegalArgumentException.class, () -> Shamir.split(secret, 0, 2, 1, 2, many, 0)).getMessage());
            assertEquals("3 shares need as many outputs, not 2", assertThrows(IllegalArgumentException.class,
                    () -> Shamir.split(secret, 0, 2, 2, 3, Arrays.copyOf(many, 2), 0)).getMessage());
            for (int x : new int[] {0, 256, -1}) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> Shamir.combine(new int[] {1, x}, new MemorySegment[] {many[0], many[1]}, 0, 2,
                                arena.allocate(2), 0));
                assertEquals("a share's x is 1 to 255, not " + x, e.getMessage());
            }
        }
    }

    // ------------------------------------------------------------ AES-GCM in Java

    @Test
    void theJavaAesGcmMatchesTheJdkPast255CounterBlocks() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (i * 13 + 5);
        }
        for (int i = 0; i < 12; i++) {
            nonce[i] = (byte) (0xf0 + i);
        }
        byte[] aad = "the header".getBytes(StandardCharsets.US_ASCII);
        for (int length : new int[] {0, 1, 15, 16, 17, 63, 64, 65, 255 * 16, 255 * 16 + 1, 256 * 16 + 40, 5000}) {
            byte[] plain = new byte[length];
            for (int i = 0; i < length; i++) {
                plain[i] = (byte) (i * 31 + 7);
            }
            Cipher jdk = Cipher.getInstance("AES/GCM/NoPadding");
            jdk.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            jdk.updateAAD(aad);
            byte[] expected = jdk.doFinal(plain);
            try (Arena arena = Arena.ofConfined(); AesKey aes = new AesKey(of(arena, key))) {
                MemorySegment sealed = arena.allocate(length + 16);
                AesGcm.encrypt(aes, of(arena, nonce), 0, of(arena, aad), 0, aad.length, of(arena, plain), 0, length,
                        sealed, 0);
                assertArrayEquals(expected, sealed.toArray(ValueLayout.JAVA_BYTE), length + " bytes");
                MemorySegment opened = arena.allocate(Math.max(1, length));
                assertTrue(AesGcm.decrypt(aes, of(arena, nonce), 0, of(arena, aad), 0, aad.length, sealed, 0, length,
                        opened, 0), "a genuine tag opens");
                assertArrayEquals(plain, opened.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE));
                MemorySegment forged = arena.allocate(length + 16);
                MemorySegment.copy(sealed, 0, forged, 0, length + 16);
                forged.set(ValueLayout.JAVA_BYTE, length + 15,
                        (byte) (forged.get(ValueLayout.JAVA_BYTE, length + 15) ^ 1));
                MemorySegment untouched = arena.allocate(Math.max(1, length));
                assertFalse(AesGcm.decrypt(aes, of(arena, nonce), 0, of(arena, aad), 0, aad.length, forged, 0, length,
                        untouched, 0), "a forged tag does not");
                assertEquals(BigInteger.ZERO, new BigInteger(1, untouched.toArray(ValueLayout.JAVA_BYTE)),
                        "and nothing is written");
            }
        }
    }
}
