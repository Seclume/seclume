package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Shamir shares as lines of text, and {@code provider=shamir}: golden lines
 * from an independent implementation, every typo refused, shares that do not
 * belong together refused, k of n files in, the secret out.
 */
class ShamirSharesTest {

    /**
     * Made in Python, apart from this code (hashlib, zlib.crc32): the secret
     * 00..1f, split 0123456789abcdef, threshold 3, coefficients (7i + 3) mod 256
     * over the secret and its 16-byte check.
     */
    static final List<String> GOLDEN = List.of(
            "seclume-share-1.0123456789abcdef.3.1.50517273745556b7b8d9dafbfcfddedfa0a142434465664748a9aacbcccdeeef6b19c7627ad10504e68ff9a6e4a4cdad.5832de69",
            "seclume-share-1.0123456789abcdef.3.2.5166bf889d8ab34964f3ca1d083f2611d7e062554097aeb9946e57c0d5e23b0caaee910208ce20d7174804401066f5a3.f37b27d5",
            "seclume-share-1.0123456789abcdef.3.3.0136cff8eddae3f9d4231aedf8cff6c16750320510e7dee9c4dee7100532cbfc7a3e21b2b89e70a7671854f0a0d62573.9b6f3d67",
            "seclume-share-1.0123456789abcdef.3.4.4bfe0cb9d2bc234f8cf966bed560249143f69f2a41990668abc7582d46f301b407c1e2f3878ec63e1036dc0e20d48155.43b6c649",
            "seclume-share-1.0123456789abcdef.3.5.1bae7cc9a2ec73ff3c29b64e2590f441f346cf7a11e97638fb77e8fd9623f144d711524337de964e60668cbe90645185.6f43f472");

    static final String CHECK = "bbc977d2ca81557496dfa91654141d7d";

    @TempDir
    Path directory;

    private static byte[] secret() {
        byte[] secret = new byte[32];
        for (int i = 0; i < 32; i++) {
            secret[i] = (byte) i;
        }
        return secret;
    }

    private static MemorySegment text(Arena arena, String line) {
        byte[] bytes = line.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static ShamirShares.Share parse(Arena arena, String line) {
        MemorySegment y = arena.allocate(ShamirShares.MAX_SECRET + ShamirShares.CHECK);
        MemorySegment text = text(arena, line);
        return ShamirShares.parse(text, (int) text.byteSize(), y);
    }

    @Test
    void theGoldenLinesAreWhatThisCodeWrites() {
        try (Arena arena = Arena.ofConfined()) {
            for (String line : GOLDEN) {
                ShamirShares.Share share = parse(arena, line);
                MemorySegment out = arena.allocate(ShamirShares.textLength(32));
                int n = ShamirShares.encode(share.split(), share.threshold(), share.x(),
                        share.y(), share.length(), out);
                assertEquals(line + "\n", new String(out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.US_ASCII));
                assertEquals(0x0123456789abcdefL, share.split());
                assertEquals(3, share.threshold());
                assertEquals(48, share.length());
            }
        }
    }

    @Test
    void theCheckIsSha256OfMagicSplitAndSecret() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(32);
            MemorySegment.copy(secret(), 0, secret, ValueLayout.JAVA_BYTE, 0, 32);
            MemorySegment check = arena.allocate(16);
            ShamirShares.check(0x0123456789abcdefL, secret, 32, check, 0);
            assertEquals(CHECK, HexFormat.of().formatHex(check.toArray(ValueLayout.JAVA_BYTE)));
        }
    }

    @Test
    void everyThreeOfTheFiveGoldenSharesGiveTheSecret() {
        for (int a = 0; a < 5; a++) {
            for (int b = a + 1; b < 5; b++) {
                for (int c = b + 1; c < 5; c++) {
                    try (Arena arena = Arena.ofConfined()) {
                        MemorySegment target = arena.allocate(64);
                        int n = ShamirShares.combine(List.of(parse(arena, GOLDEN.get(c)),
                                parse(arena, GOLDEN.get(a)), parse(arena, GOLDEN.get(b))), target);
                        assertEquals(32, n);
                        assertArrayEquals(secret(), target.asSlice(0, 32).toArray(ValueLayout.JAVA_BYTE),
                                a + "," + b + "," + c);
                    }
                }
            }
        }
    }

    @Test
    void anyChangeToAnyCharacterIsRefused() {
        String line = GOLDEN.get(0);
        String alphabet = "0123456789abcdef.-sx";
        try (Arena arena = Arena.ofConfined()) {
            for (int i = 0; i < line.length(); i++) {
                for (char replacement : alphabet.toCharArray()) {
                    if (replacement == line.charAt(i)) {
                        continue;
                    }
                    String changed = line.substring(0, i) + replacement + line.substring(i + 1);
                    assertThrows(SecretUnavailableException.class, () -> parse(arena, changed),
                            "position " + i + " as " + replacement);
                }
            }
        }
    }

    @Test
    void aMissingOrDoubledCharacterIsRefused() {
        String line = GOLDEN.get(1);
        try (Arena arena = Arena.ofConfined()) {
            for (int i = 0; i < line.length(); i++) {
                String dropped = line.substring(0, i) + line.substring(i + 1);
                String doubled = line.substring(0, i) + line.charAt(i) + line.substring(i);
                assertThrows(SecretUnavailableException.class, () -> parse(arena, dropped), "drop " + i);
                assertThrows(SecretUnavailableException.class, () -> parse(arena, doubled), "double " + i);
            }
        }
    }

    @Test
    void lineBreaksAndTrailingBlanksAreAllowed() {
        try (Arena arena = Arena.ofConfined()) {
            assertEquals(1, parse(arena, GOLDEN.get(0) + "\r\n").x());
            assertEquals(1, parse(arena, GOLDEN.get(0) + " \n\n").x());
        }
    }

    @Test
    void sharesOfAnotherSplitAreRefused() throws IOException {
        Path other = Files.createDirectories(directory.resolve("other"));
        Path secretFile = Files.write(directory.resolve("secret"), secret());
        ShamirShares.split(new FileSecretProvider(secretFile, 256), 3, 5, other);
        String foreign = Files.readString(other.resolve("share-3-of-5.txt"));
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(64);
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> ShamirShares.combine(List.of(parse(arena, GOLDEN.get(0)),
                            parse(arena, GOLDEN.get(1)), parse(arena, foreign)), target));
            assertTrue(e.getMessage().contains("another split"), e.getMessage());
            assertAllZero(target);
        }
    }

    @Test
    void theSameShareTwiceIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(64);
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> ShamirShares.combine(List.of(parse(arena, GOLDEN.get(0)),
                            parse(arena, GOLDEN.get(1)), parse(arena, GOLDEN.get(0))), target));
            assertTrue(e.getMessage().contains("twice"), e.getMessage());
        }
    }

    @Test
    void tooFewSharesAreRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(64);
            assertThrows(SecretUnavailableException.class, () -> ShamirShares.combine(
                    List.of(parse(arena, GOLDEN.get(0)), parse(arena, GOLDEN.get(1))), target));
            assertAllZero(target);
        }
    }

    /**
     * A share whose value was altered and whose checksum was made to fit -
     * someone who meant it, not a typo. The CRC lets it through, the check
     * after combining does not.
     */
    @Test
    void aForgedShareFailsTheCheckAfterCombining() {
        String line = GOLDEN.get(2);
        int valueStart = line.lastIndexOf('.', line.lastIndexOf('.') - 1) + 1;
        char[] chars = line.substring(0, line.lastIndexOf('.')).toCharArray();
        chars[valueStart + 10] = chars[valueStart + 10] == '0' ? '1' : '0';
        String body = new String(chars);
        CRC32 crc = new CRC32();
        crc.update(body.getBytes(StandardCharsets.US_ASCII));
        String forged = body + "." + String.format("%08x", crc.getValue());
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(64);
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> ShamirShares.combine(List.of(parse(arena, GOLDEN.get(0)),
                            parse(arena, GOLDEN.get(1)), parse(arena, forged)), target));
            assertTrue(e.getMessage().contains("do not give back"), e.getMessage());
            assertAllZero(target);
        }
    }

    @Test
    void theChecksumIsCrc32() {
        java.util.SplittableRandom random = new java.util.SplittableRandom(5);
        try (Arena arena = Arena.ofConfined()) {
            for (int round = 0; round < 200; round++) {
                byte[] data = new byte[random.nextInt(300)];
                for (int i = 0; i < data.length; i++) {
                    data[i] = (byte) random.nextInt(256);
                }
                MemorySegment segment = arena.allocate(Math.max(1, data.length));
                MemorySegment.copy(data, 0, segment, ValueLayout.JAVA_BYTE, 0, data.length);
                CRC32 crc = new CRC32();
                crc.update(data);
                assertEquals((int) crc.getValue(), ShamirShares.crc32(segment, data.length));
            }
        }
    }

    @Test
    void hexDigitsAreReadWithoutBranchesAndCorrectly() {
        for (int c = 0; c < 256; c++) {
            int expected = Character.digit((char) c, 16);
            if (c > 127) {
                expected = -1;
            }
            assertEquals(expected, ShamirShares.hexValue((byte) c), "byte " + c);
        }
    }

    @Test
    void theRefusalsDoNotQuoteTheShare() {
        String line = GOLDEN.get(3);
        String value = line.split("\\.")[4];
        try (Arena arena = Arena.ofConfined()) {
            for (int i = 0; i < line.length(); i += 3) {
                String changed = line.substring(0, i) + (line.charAt(i) == 'x' ? 'y' : 'x')
                        + line.substring(i + 1);
                SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                        () -> parse(arena, changed));
                for (int at = 0; at + 6 <= value.length(); at += 6) {
                    assertFalse(e.getMessage().contains(value.substring(at, at + 6)), e.getMessage());
                }
            }
        }
    }

    @Test
    void splitWritesOwnerOnlyFilesAndNeverOverwrites() throws IOException {
        Path secretFile = Files.write(directory.resolve("secret"), secret());
        Path out = directory.resolve("shares");
        List<Path> files = ShamirShares.split(new FileSecretProvider(secretFile, 256), 2, 3, out);
        assertEquals(3, files.size());
        for (Path file : files) {
            assertTrue(Files.readString(file).startsWith("seclume-share-1."));
            if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
                assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
            }
        }
        assertThrows(FileAlreadyExistsException.class,
                () -> ShamirShares.split(new FileSecretProvider(secretFile, 256), 2, 3, out));
    }

    @Test
    void splitRefusesAnEmptyOrOversizedSecret() throws IOException {
        Path empty = Files.write(directory.resolve("empty"), new byte[0]);
        assertThrows(SecretUnavailableException.class,
                () -> ShamirShares.split(new FileSecretProvider(empty, 256), 2, 3, directory.resolve("a")));
        Path big = Files.write(directory.resolve("big"), new byte[ShamirShares.MAX_SECRET + 1]);
        assertThrows(SecretUnavailableException.class, () -> ShamirShares.split(
                new FileSecretProvider(big, 4096), 2, 3, directory.resolve("b")));
    }

    // ---- provider=shamir -------------------------------------------------

    private Map<String, String> settings(List<Path> shares) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "shamir");
        for (int i = 0; i < shares.size(); i++) {
            settings.put("share." + (i + 1) + ".provider", "file");
            settings.put("share." + (i + 1) + ".path", shares.get(i).toString());
        }
        return settings;
    }

    private static byte[] read(SecretProvider provider) {
        try (SecretScope scope = SecretScope.fromProvider(provider)) {
            return scope.segment().asSlice(0, scope.length()).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    private List<Path> fiveShares(byte[] secret) throws IOException {
        Path secretFile = Files.write(directory.resolve("s-" + secret.length), secret);
        return ShamirShares.split(new FileSecretProvider(secretFile, 256), 3, 5,
                directory.resolve("shares-" + secret.length));
    }

    @Test
    void threeOfFiveFilesGiveTheSecretWhicheverAreThere() throws IOException {
        byte[] secret = "a master key nobody holds alone".getBytes(StandardCharsets.US_ASCII);
        List<Path> files = fiveShares(secret);
        for (int missingA = 0; missingA < 5; missingA++) {
            for (int missingB = missingA + 1; missingB < 5; missingB++) {
                List<Path> present = new ArrayList<>(files);
                present.set(missingA, directory.resolve("absent-a"));
                present.set(missingB, directory.resolve("absent-b"));
                try (SecretProvider provider = SecretProviders.of(settings(present))) {
                    assertArrayEquals(secret, read(provider), "without " + missingA + " and " + missingB);
                }
            }
        }
    }

    @Test
    void twoOfFiveAreNotEnoughAndTheMessageSaysWhichAreMissing() throws IOException {
        List<Path> files = fiveShares(secret());
        List<Path> present = new ArrayList<>(files);
        for (int i = 2; i < 5; i++) {
            present.set(i, directory.resolve("absent-" + i));
        }
        try (SecretProvider provider = SecretProviders.of(settings(present))) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(e.getMessage().contains("3 Shamir shares are needed and 2 could be read"),
                    e.getMessage());
            assertTrue(e.getMessage().contains("share.3") && e.getMessage().contains("share.5"),
                    e.getMessage());
        }
    }

    @Test
    void aBrokenShareIsAnErrorNotSilentlyPassedOver() throws IOException {
        List<Path> files = fiveShares(secret());
        String broken = Files.readString(files.get(0)).replace('.', ',');
        Files.writeString(files.get(0), broken);
        try (SecretProvider provider = SecretProviders.of(settings(files))) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(e.getMessage().startsWith("share.1: a Shamir share is refused"), e.getMessage());
        }
    }

    @Test
    void aThresholdFloorRefusesAWeakerSplit() throws IOException {
        List<Path> files = fiveShares(secret());
        Map<String, String> settings = settings(files);
        settings.put("threshold", "4");
        try (SecretProvider provider = SecretProviders.of(settings)) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(e.getMessage().contains("fewer than threshold=4"), e.getMessage());
        }
        settings.put("threshold", "3");
        try (SecretProvider provider = SecretProviders.of(settings)) {
            assertArrayEquals(secret(), read(provider));
        }
    }

    @Test
    void theConfigurationIsChecked() {
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(Map.of("provider", "shamir")));
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(Map.of(
                "provider", "shamir", "share.1.provider", "file", "share.1.path", "/x")));
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(Map.of(
                "provider", "shamir", "threshold", "three",
                "share.1.provider", "file", "share.1.path", "/x",
                "share.2.provider", "file", "share.2.path", "/y")));
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(Map.of(
                "provider", "shamir", "threshold", "3",
                "share.1.provider", "file", "share.1.path", "/x",
                "share.2.provider", "file", "share.2.path", "/y")));
    }

    @Test
    void theGoldenSharesWorkThroughTheProviderToo() throws IOException {
        List<Path> files = new ArrayList<>();
        for (int i : new int[] {4, 0, 2}) {
            files.add(Files.writeString(directory.resolve("golden-" + i), GOLDEN.get(i) + "\n"));
        }
        try (SecretProvider provider = SecretProviders.of(settings(files))) {
            assertArrayEquals(secret(), read(provider));
        }
    }

    @Test
    void theTargetHoldsTheSecretAndNothingAfterIt() throws IOException {
        List<Path> files = fiveShares(secret());
        try (SecretProvider provider = SecretProviders.of(settings(files));
             Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int n = provider.writeSecret(target);
            assertEquals(32, n);
            assertAllZero(target.asSlice(32));
        }
    }

    @Test
    void aTargetTooSmallIsRefused() throws IOException {
        List<Path> files = fiveShares(secret());
        try (SecretProvider provider = SecretProviders.of(settings(files));
             Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(16);
            assertThrows(SecretUnavailableException.class, () -> provider.writeSecret(target));
            assertAllZero(target);
        }
    }

    private static void assertAllZero(MemorySegment segment) {
        for (long i = 0; i < segment.byteSize(); i++) {
            assertEquals(0, segment.get(ValueLayout.JAVA_BYTE, i), "byte " + i);
        }
    }
}
