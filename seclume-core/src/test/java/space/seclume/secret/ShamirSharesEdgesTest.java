package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.CRC32;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.crypto.Shamir;

/**
 * Shamir shares at the edges of their format: the longest line, numbers of
 * one, two and three digits written and read, the thresholds and numbers just
 * inside and outside 2/1 to 255, the shortest and longest values, a value
 * buffer of exactly the size, hex in either case and a pair with only one bad
 * digit, the shortest text that is looked at, a split identifier one digit
 * short, a target of exactly the secret's length, and splits of 1 and 1024
 * bytes with identifiers of their own. Written against the mutants PIT left
 * alive in this package.
 */
class ShamirSharesEdgesTest {

    private static final String MAGIC = "seclume-share-1";

    @TempDir
    Path directory;

    /** A share line with a correct checksum, whatever its fields say. */
    private static String line(String split, String threshold, String x, String y) {
        String body = MAGIC + "." + split + "." + threshold + "." + x + "." + y;
        CRC32 crc = new CRC32();
        crc.update(body.getBytes(StandardCharsets.US_ASCII));
        return body + "." + String.format(Locale.ROOT, "%08x", crc.getValue());
    }

    private static String hexValue(int bytes) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < bytes; i++) {
            out.append(String.format(Locale.ROOT, "%02x", (i * 37 + 11) & 0xff));
        }
        return out.toString();
    }

    private static MemorySegment text(Arena arena, String line) {
        byte[] bytes = line.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(Math.max(1, bytes.length));
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static ShamirShares.Share parse(Arena arena, String line, long ySize) {
        MemorySegment text = text(arena, line);
        return ShamirShares.parse(text, line.length(), arena.allocate(ySize));
    }

    private static ShamirShares.Share parse(Arena arena, String line) {
        return parse(arena, line, ShamirShares.MAX_SECRET + ShamirShares.CHECK);
    }

    private static String refusal(String line) {
        try (Arena arena = Arena.ofConfined()) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class, () -> parse(arena, line));
            return e.getMessage();
        }
    }

    // ---------------------------------------------------------- writing

    @Test
    void theLongestLineIsExactlyWhatTextLengthSays() {
        assertEquals(83, ShamirShares.textLength(0));
        assertEquals(85, ShamirShares.textLength(1));
        assertEquals(83 + 2 * ShamirShares.MAX_SECRET, ShamirShares.textLength(ShamirShares.MAX_SECRET));
        for (int length : new int[] {1, 32, ShamirShares.MAX_SECRET}) {
            try (Arena arena = Arena.ofConfined()) {
                int payload = length + ShamirShares.CHECK;
                MemorySegment y = arena.allocate(payload);
                MemorySegment text = arena.allocate(ShamirShares.textLength(length));
                int n = ShamirShares.encode(-1L, 255, 255, y, payload, text);
                assertEquals(ShamirShares.textLength(length), n,
                        "a threshold and a number of three digits, newline included: the buffer is full");
            }
        }
    }

    @Test
    void numbersAreWrittenWithOneTwoOrThreeDigits() {
        for (int x : new int[] {1, 9, 10, 99, 100, 199, 200, 255}) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment y = arena.allocate(ShamirShares.CHECK + 1);
                MemorySegment text = arena.allocate(ShamirShares.textLength(1));
                int threshold = Math.max(2, x);
                int n = ShamirShares.encode(0x0123456789abcdefL, threshold, x, y, ShamirShares.CHECK + 1, text);
                String written = new String(text.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.US_ASCII);
                assertTrue(written.startsWith(MAGIC + ".0123456789abcdef." + threshold + "." + x + ".00"), written);
                assertTrue(written.endsWith("\n"));
                ShamirShares.Share back = parse(arena, written);
                assertEquals(threshold, back.threshold());
                assertEquals(x, back.x());
                assertEquals(0x0123456789abcdefL, back.split());
            }
        }
    }

    // ---------------------------------------------------------- reading

    @Test
    void aThresholdIsTwoTo255AndANumberOneTo255() {
        String y = hexValue(ShamirShares.CHECK + 4);
        try (Arena arena = Arena.ofConfined()) {
            assertEquals(2, parse(arena, line("0123456789abcdef", "2", "1", y)).threshold());
            assertEquals(Shamir.MAX_SHARES, parse(arena, line("0123456789abcdef", "255", "255", y)).threshold());
            assertEquals(Shamir.MAX_SHARES, parse(arena, line("0123456789abcdef", "3", "255", y)).x());
            assertEquals(2, parse(arena, line("0123456789abcdef", "002", "001", y)).threshold(), "three digits");
        }
        assertTrue(refusal(line("0123456789abcdef", "1", "1", y)).endsWith("its threshold is 1, not 2 to 255"));
        assertTrue(refusal(line("0123456789abcdef", "256", "1", y)).endsWith("its threshold is 256, not 2 to 255"));
        assertTrue(refusal(line("0123456789abcdef", "3", "0", y)).endsWith("its number is 0, not 1 to 255"));
        assertTrue(refusal(line("0123456789abcdef", "3", "256", y)).endsWith("its number is 256, not 1 to 255"));
    }

    @Test
    void aNumberIsOneToThreeAsciiDigits() {
        String y = hexValue(ShamirShares.CHECK + 4);
        for (String wrong : new String[] {"", "/", ":", "0002", "1234"}) {
            String message = refusal(line("0123456789abcdef", wrong, "1", y));
            assertTrue(message.endsWith("its threshold is not a number of one to three digits"),
                    "'" + wrong + "': " + message);
        }
        for (String wrong : new String[] {"", "/", "0001"}) {
            String message = refusal(line("0123456789abcdef", "3", wrong, y));
            assertTrue(message.endsWith("its number is not a number of one to three digits"),
                    "'" + wrong + "': " + message);
        }
        for (String wrong : new String[] {"3:", "3/"}) {
            String message = refusal(line("0123456789abcdef", wrong, "1", y));
            assertTrue(message.endsWith("its fields are not separated by '.' where they should be"),
                    "'" + wrong + "': " + message);
        }
    }

    @Test
    void aValueIsFromSeventeenTo1040BytesInAnEvenNumberOfDigits() {
        try (Arena arena = Arena.ofConfined()) {
            assertEquals(ShamirShares.CHECK + 1,
                    parse(arena, line("0123456789abcdef", "3", "1", hexValue(ShamirShares.CHECK + 1))).length());
            assertEquals(ShamirShares.MAX_SECRET + ShamirShares.CHECK, parse(arena, line("0123456789abcdef", "3", "1",
                    hexValue(ShamirShares.MAX_SECRET + ShamirShares.CHECK))).length());
        }
        String expected = "its value is %d hex digits, not an even number from 34 to 2080";
        for (String y : new String[] {hexValue(ShamirShares.CHECK), hexValue(ShamirShares.CHECK + 1) + "0",
                hexValue(ShamirShares.MAX_SECRET + ShamirShares.CHECK + 1)}) {
            assertTrue(refusal(line("0123456789abcdef", "3", "1", y)).endsWith(expected.formatted(y.length())),
                    y.length() + " digits");
        }
    }

    @Test
    void theValueBufferMayBeExactlyTheValuesSize() {
        String line = line("0123456789abcdef", "3", "1", hexValue(40));
        try (Arena arena = Arena.ofConfined()) {
            assertEquals(40, parse(arena, line, 40).length());
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class, () -> parse(arena, line, 39));
            assertTrue(e.getMessage().endsWith("its value does not fit"), e.getMessage());
        }
    }

    @Test
    void hexIsReadInEitherCaseAndOneBadDigitOfAPairIsEnough() {
        String lower = hexValue(20).replace('0', 'a');
        try (Arena arena = Arena.ofConfined()) {
            ShamirShares.Share small = parse(arena, line("abcdef0123456789", "3", "1", lower));
            byte[] first = small.y().asSlice(0, 20).toArray(ValueLayout.JAVA_BYTE);
            ShamirShares.Share large = parse(arena, line("ABCDEF0123456789", "3", "1", lower.toUpperCase(Locale.ROOT)));
            assertArrayEquals(first, large.y().asSlice(0, 20).toArray(ValueLayout.JAVA_BYTE));
            assertEquals(small.split(), large.split());
        }
        String y = hexValue(20);
        for (String pair : new String[] {"0g", "g0", "0G", ".0", "0 "}) {
            String bad = pair + y.substring(2);
            assertTrue(refusal(line("0123456789abcdef", "3", "1", bad)).endsWith("its value is not hex"), pair);
        }
    }

    @Test
    void theShortestTextThatIsLookedAtIsTwentyFiveCharacters() {
        // The magic, a dot, eight digits and their dot: 25 characters, and then whatever is wrong.
        String twentyFive = MAGIC + ".12345678.";
        assertEquals(25, (MAGIC + ".00000000.").length());
        assertTrue(refusal(MAGIC + "." + "0".repeat(9)).contains("checksum"),
                "25 characters are read as a share: " + refusal(MAGIC + "." + "0".repeat(9)));
        assertTrue(refusal(twentyFive.substring(0, 24)).endsWith("too short to be a share"));
        assertTrue(refusal(MAGIC + "." + "0".repeat(8) + "\r\n ").endsWith("too short to be a share"),
                "trailing line breaks and blanks do not count");
    }

    @Test
    void aSplitIdentifierIsSixteenHexDigits() {
        String y = hexValue(20);
        assertTrue(refusal(line("0123456789abcde", "3", "1", y)).endsWith("its split identifier is not 16 hex digits"));
        assertTrue(refusal(line("0123456789abcdeg", "3", "1", y)).endsWith("its split identifier is not 16 hex digits"));
        assertTrue(refusal(line("0123456789abcdef0", "3", "1", y))
                .endsWith("its fields are not separated by '.' where they should be"));
    }

    @Test
    void aChecksumThatIsNotHexDoesNotMatch() {
        String good = line("0123456789abcdef", "3", "1", hexValue(20));
        String bad = good.substring(0, good.length() - 1) + "g";
        assertTrue(refusal(bad).endsWith("its checksum does not match - a digit is wrong or missing"));
        String upper = good.substring(0, good.length() - 8) + good.substring(good.length() - 8).toUpperCase(Locale.ROOT);
        try (Arena arena = Arena.ofConfined()) {
            assertEquals(1, parse(arena, upper).x(), "the checksum in capitals is the same checksum");
        }
    }

    // ---------------------------------------------------------- splitting and combining

    private static byte[] read(MemorySegment target, int length) {
        return target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
    }

    private List<ShamirShares.Share> sharesOf(Arena arena, List<Path> files) throws IOException {
        List<ShamirShares.Share> shares = new ArrayList<>();
        for (Path file : files) {
            String line = Files.readString(file, StandardCharsets.US_ASCII);
            shares.add(parse(arena, line));
        }
        return shares;
    }

    @Test
    void secretsOfOneAnd1024BytesSplitAndCombineIntoATargetOfExactlyTheirLength() throws IOException {
        for (int length : new int[] {1, ShamirShares.MAX_SECRET}) {
            byte[] secret = new byte[length];
            for (int i = 0; i < length; i++) {
                secret[i] = (byte) (0xa5 ^ i);
            }
            Path file = Files.write(directory.resolve("secret-" + length), secret);
            List<Path> files = ShamirShares.split(new FileSecretProvider(file, 2048), 2, 3,
                    directory.resolve("shares-" + length));
            assertEquals(List.of("share-1-of-3.txt", "share-2-of-3.txt", "share-3-of-3.txt"),
                    files.stream().map(p -> p.getFileName().toString()).toList());
            try (Arena arena = Arena.ofConfined()) {
                List<ShamirShares.Share> shares = sharesOf(arena, files);
                assertEquals(List.of(1, 2, 3), shares.stream().map(ShamirShares.Share::x).toList(),
                        "share n of the file share-n");
                MemorySegment exact = arena.allocate(length);
                assertEquals(length, ShamirShares.combine(shares.subList(1, 3), exact));
                assertArrayEquals(secret, read(exact, length));
                MemorySegment short1 = arena.allocate(length - 1 == 0 ? 1 : length - 1);
                if (length > 1) {
                    SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                            () -> ShamirShares.combine(shares.subList(0, 2), short1));
                    assertTrue(e.getMessage().endsWith("the secret is " + length + " bytes and does not fit into the "
                            + (length - 1) + " bytes provided"), e.getMessage());
                }
                SecretUnavailableException many = assertThrows(SecretUnavailableException.class,
                        () -> ShamirShares.combine(shares, exact));
                assertTrue(many.getMessage().endsWith("2 shares are needed, 3 were given"), many.getMessage());
            }
        }
    }

    @Test
    void eachSplitDrawsItsOwnIdentifier() throws IOException {
        Path file = Files.write(directory.resolve("secret"), new byte[] {1, 2, 3});
        Set<Long> splits = new HashSet<>();
        for (int i = 0; i < 4; i++) {
            List<Path> files = ShamirShares.split(new FileSecretProvider(file, 16), 2, 2, directory.resolve("s" + i));
            try (Arena arena = Arena.ofConfined()) {
                splits.add(sharesOf(arena, files).get(0).split());
            }
        }
        assertEquals(4, splits.size(), "a random identifier for each split: " + splits);
        assertNotEquals(Set.of(0L), splits);
    }

    @Test
    void aSecretOf1025BytesIsNotSplit() throws IOException {
        for (int length : new int[] {ShamirShares.MAX_SECRET + 1, 4096}) {
            Path file = Files.write(directory.resolve("bad-" + length), new byte[length]);
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> ShamirShares.split(new FileSecretProvider(file, 4096), 2, 3, directory.resolve("x" + length)));
            assertEquals("a secret of 1 to 1024 bytes can be split, not " + length, e.getMessage());
        }
    }
}
