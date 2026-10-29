package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Redaction on dumps written byte by byte, so that every byte of the result
 * can be accounted for: what was overwritten, with what, and that nothing
 * else changed. {@code HeapCheckTest} redacts a real dump.
 */
class RedactorTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long STRING = 0x100;
    private static final long CONFIG = 0x101;

    private static String alnum(int length) {
        String letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(letters.charAt(RANDOM.nextInt(letters.length())));
        }
        return out.toString();
    }

    private static boolean contains(byte[] data, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** A dump: a String with a password in a byte[], one in a char[], and a config object. */
    private record Fixture(Path dump, String password, String unicode, long passwordAt,
            long unicodeAt, long hashAt, int hash) {
    }

    private static Fixture fixture(Path directory, String password, String unicode,
            String... more) throws IOException {
        TestHprof h = new TestHprof(4);
        h.loadClass(STRING, "java/lang/String");
        h.loadClass(CONFIG, "com/acme/Config");
        // value first, then the int hash - as the instance is written, own fields in order.
        h.classDump(STRING, 0, new Object[0][], new Object[][] {{"value", 2}, {"hash", 10}});
        h.classDump(CONFIG, 0, new Object[0][], new Object[][] {{"password", 2},
                {"unicode", 2}});
        long[] at = new long[1];
        long passwordAt = h.byteArray(0x400, password.getBytes(StandardCharsets.ISO_8859_1), at);
        long unicodeAt = h.charArray(0x401, unicode);
        for (int i = 0; i < more.length; i++) {
            h.byteArray(0x500 + i, more[i].getBytes(StandardCharsets.US_ASCII), at);
        }
        int hash = password.hashCode();
        long beforeInstance = h.heap.size();
        h.instance(0x600, STRING, 0x400, hash);         // the password's String, hash computed
        long hashAt = beforeInstance + 1 + 4 + 4 + 4 + 4 + 4;   // tag, id, trace, class, length, value
        h.instance(0x601, STRING, 0x401, 0);
        h.instance(0x700, CONFIG, 0x600, 0x601);
        long segment = h.finish();
        Path dump = Files.write(directory.resolve("app.hprof"), h.file.toByteArray());
        return new Fixture(dump, password, unicode, segment + passwordAt, segment + unicodeAt,
                segment + hashAt, hash);
    }

    @Test
    void aNamedSecretIsOverwrittenInEveryEncodingAndNothingElseChanges(@TempDir Path directory)
            throws IOException {
        String password = "Tr0ub4dor-" + alnum(12);
        String base64 = Base64.getEncoder().encodeToString(
                password.getBytes(StandardCharsets.UTF_8));
        Fixture f = fixture(directory, password, password, "basic " + base64 + " end");
        Path out = directory.resolve("redacted.hprof");

        Redactor.Report report = Redactor.redact(f.dump(), out,
                List.of(Redactor.Needle.text("db-password", password)), false, Set.of());

        byte[] before = Files.readAllBytes(f.dump());
        byte[] after = Files.readAllBytes(out);
        assertEquals(before.length, after.length, "the dump changed its length");
        assertFalse(contains(after, password.getBytes(StandardCharsets.UTF_8)));
        assertFalse(contains(after, password.getBytes(StandardCharsets.UTF_16BE)));
        assertFalse(contains(after, base64.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(3, report.named().get("db-password"),
                "Latin-1 byte[], UTF-16 char[] and Base64");

        // overwritten with *, in each place's own encoding
        byte[] stars = "*".repeat(password.length()).getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(stars, slice(after, f.passwordAt(), password.length()));
        assertArrayEquals("*".repeat(password.length()).getBytes(StandardCharsets.UTF_16BE),
                slice(after, f.unicodeAt(), 2 * password.length()));

        // the String's hash is gone with its text
        assertEquals(f.hash(), ByteBuffer.wrap(slice(before, f.hashAt(), 4)).getInt(),
                "the fixture puts the hash where the test looks");
        assertEquals(0, ByteBuffer.wrap(slice(after, f.hashAt(), 4)).getInt());
        assertEquals(2, report.stringHashes(), "both Strings held the password");

        // and nothing else moved: every byte outside the regions is the same
        int changed = 0;
        for (int i = 0; i < before.length; i++) {
            if (before[i] != after[i]) {
                changed++;
            }
        }
        assertTrue(changed <= password.length() * 3 + base64.length() + 4,
                changed + " bytes changed");
        // and the result is still a dump its structure can be read from
        assertEquals("String in com.acme.Config.password",
                Attribution.of(out, new long[] {f.passwordAt()}).get(f.passwordAt()));
        // the original is untouched
        assertTrue(contains(Files.readAllBytes(f.dump()),
                password.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void discoveryOverwritesTheValueNotTheWholeMatch(@TempDir Path directory)
            throws IOException {
        String dbPassword = alnum(18);
        String url = "postgresql://app:" + dbPassword + "@db.internal:5432/app";
        String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJ" + alnum(60) + "." + alnum(64);
        String keyBody = alnum(64) + "\n" + alnum(64) + "\n" + alnum(20);
        String pem = "-----BEGIN PRIVATE KEY-----\n" + keyBody + "\n-----END PRIVATE KEY-----";
        Fixture f = fixture(directory, "nothing-here", "nothing", url, jwt, pem);
        Path out = directory.resolve("redacted.hprof");

        Redactor.Report report = Redactor.redact(f.dump(), out, List.of(), true, Set.of());

        String after = new String(Files.readAllBytes(out), StandardCharsets.ISO_8859_1);
        assertTrue(after.contains("postgresql://app:" + "*".repeat(18) + "@db.internal:5432/app"),
                "the URL around the password should stay readable");
        assertFalse(after.contains(dbPassword));
        assertFalse(after.contains(jwt.substring(30)));
        for (String line : keyBody.split("\n")) {
            assertFalse(after.contains(line), "a line of the key is left: the whole block goes");
        }
        assertTrue(report.discovered().valuesByDetector().keySet()
                .containsAll(List.of("url-password", "jwt", "private-key")));
        assertTrue(Discovery.scan(out, Set.of()).clean());
    }

    /**
     * What discovery finds has copies where it has no shape: the password of
     * a URL in a field of its own, a JWT's payload split off, a key's line, a
     * token's body without its prefix. Each goes too, in its own encoding.
     */
    @Test
    void echoesOfADiscoveredCredentialGoWhereverTheyLie(@TempDir Path directory)
            throws IOException {
        String dbPassword = alnum(14);
        String url = "postgresql://app:" + dbPassword + "@db.internal:5432/app";
        String payload = "eyJ" + alnum(40);
        String jwt = "eyJhbGciOiJSUzI1NiJ9." + payload + "." + alnum(43);
        String line = alnum(64);
        String pem = "-----BEGIN PRIVATE KEY-----\n" + line + "\n" + alnum(64)
                + "\n-----END PRIVATE KEY-----";
        String body = alnum(36);
        TestHprof h = new TestHprof(4);
        long[] at = new long[1];
        long id = 0x500;
        for (String text : List.of(url, jwt, pem, "ghp_" + body)) {
            h.byteArray(id++, text.getBytes(StandardCharsets.US_ASCII), at);
        }
        h.byteArray(0x600, dbPassword.getBytes(StandardCharsets.US_ASCII), at);  // the config field
        h.charArray(0x601, dbPassword);                                       // and as a char[]
        h.byteArray(0x602, payload.getBytes(StandardCharsets.US_ASCII), at);
        h.byteArray(0x603, line.getBytes(StandardCharsets.US_ASCII), at);
        h.byteArray(0x604, body.getBytes(StandardCharsets.US_ASCII), at);
        h.finish();
        Path dump = Files.write(directory.resolve("app.hprof"), h.file.toByteArray());
        Path out = directory.resolve("redacted.hprof");

        Redactor.Report report = Redactor.redact(dump, out, List.of(), true, Set.of());

        byte[] after = Files.readAllBytes(out);
        for (String value : List.of(dbPassword, payload, line, body)) {
            assertFalse(contains(after, value.getBytes(StandardCharsets.US_ASCII)), value);
        }
        assertFalse(contains(after, dbPassword.getBytes(StandardCharsets.UTF_16BE)));
        assertEquals(5, report.echoes(), "password twice, payload, line, body");
        assertTrue(contains(after, "@db.internal:5432/app".getBytes(StandardCharsets.US_ASCII)));
    }

    /**
     * A short discovered password is not looked for elsewhere: eight bytes
     * and fewer match by chance, in the dump's own records, and overwriting
     * those would break the dump. The match itself still goes.
     */
    @Test
    void aShortPasswordIsNotLookedForElsewhere(@TempDir Path directory) throws IOException {
        String shortPassword = alnum(Redactor.SHORTEST_ECHO - 1);
        TestHprof h = new TestHprof(4);
        long[] at = new long[1];
        h.byteArray(0x500, ("mysql://root:" + shortPassword + "@localhost/db")
                .getBytes(StandardCharsets.US_ASCII), at);
        long standalone = h.byteArray(0x501, shortPassword.getBytes(StandardCharsets.US_ASCII),
                at);
        long segment = h.finish();
        Path dump = Files.write(directory.resolve("app.hprof"), h.file.toByteArray());
        Path out = directory.resolve("redacted.hprof");
        Redactor.Report report = Redactor.redact(dump, out, List.of(), true, Set.of());
        byte[] after = Files.readAllBytes(out);
        assertTrue(contains(after, ("mysql://root:" + "*".repeat(shortPassword.length())
                + "@localhost").getBytes(StandardCharsets.US_ASCII)));
        assertEquals(0, report.echoes());
        assertArrayEquals(shortPassword.getBytes(StandardCharsets.US_ASCII),
                slice(after, segment + standalone, shortPassword.length()));
    }

    @Test
    void thePiecesOfAValueAreWhereItsStructureSplitsIt() {
        String token = "sk_live_" + "A".repeat(20);
        java.util.Set<ByteBuffer> pieces = new java.util.LinkedHashSet<>();
        Redactor.Echoes.pieces(token.getBytes(StandardCharsets.US_ASCII), pieces);
        assertEquals(java.util.Set.of(ByteBuffer.wrap("A".repeat(20)
                .getBytes(StandardCharsets.US_ASCII))), pieces, "sk_ and live_ both go");
        assertEquals(4, Redactor.Echoes.prefix("ghp_x".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(0, Redactor.Echoes.prefix("x_abc".getBytes(StandardCharsets.US_ASCII)),
                "one letter is no prefix");
        assertEquals(0, Redactor.Echoes.prefix("abcdefgh_x".getBytes(StandardCharsets.US_ASCII)),
                "eight letters are no prefix");
        assertEquals(0, Redactor.Echoes.prefix("ghp_".getBytes(StandardCharsets.US_ASCII)),
                "a prefix needs a body");

        pieces.clear();
        String jwt = "eyJ" + "a".repeat(16) + ".eyJ" + "b".repeat(16) + "." + "c".repeat(15);
        Redactor.Echoes.pieces(jwt.getBytes(StandardCharsets.US_ASCII), pieces);
        assertEquals(2, pieces.size(), "two segments long enough, the third too short");
    }

    /** Echoes on every window edge: all found, none twice - as for a named secret. */
    @Test
    void echoesAreFoundAcrossWindows(@TempDir Path directory) throws IOException {
        String password = alnum(12);
        String url = "https://u:" + password + "@host.example";
        byte[] filler = new byte[997];
        java.util.Arrays.fill(filler, (byte) 0xa5);
        java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
        data.writeBytes(url.getBytes(StandardCharsets.US_ASCII));
        for (int i = 0; i < 200; i++) {
            data.write(filler, 0, RANDOM.nextInt(filler.length));
            data.writeBytes(password.getBytes(StandardCharsets.US_ASCII));
        }
        Path file = Files.write(directory.resolve("raw.bin"), data.toByteArray());
        List<Redactor.Region> found = new ArrayList<>();
        Discovery.scan(file, Set.of(), o -> found.add(new Redactor.Region(
                o.valuePosition(), o.valueLength(), Redactor.Fill.of(o.encoding()))));
        Redactor.Echoes echoes = Redactor.Echoes.of(file, found);
        for (int window : new int[] {64, 100, 1000, 4096, 1 << 20}) {
            List<Redactor.Region> regions = new ArrayList<>();
            assertEquals(201, echoes.find(file, regions, window), "with windows of " + window);
            assertEquals(201, regions.stream().map(Redactor.Region::position).distinct()
                    .count(), "an echo counted twice with windows of " + window);
        }
    }

    @Test
    void aBinarySecretIsZeroed(@TempDir Path directory) throws IOException {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        key[0] = (byte) 0xff;
        TestHprof h = new TestHprof(8);
        long[] at = new long[1];
        long keyAt = h.byteArray(0x900, key, at);
        long segment = h.finish();
        Path dump = Files.write(directory.resolve("key.hprof"), h.file.toByteArray());
        Path out = directory.resolve("redacted.hprof");
        Redactor.redact(dump, out, List.of(Redactor.Needle.bytes("key.der", key)), false,
                Set.of());
        assertArrayEquals(new byte[32], slice(Files.readAllBytes(out), segment + keyAt, 32));
    }

    /** Small windows, so that occurrences fall on every edge: all found, none twice. */
    @Test
    void windowsNeitherLoseNorDoubleAnOccurrence(@TempDir Path directory) throws IOException {
        String secret = "s3cr3t-" + alnum(20);
        byte[] filler = new byte[997];
        java.util.Arrays.fill(filler, (byte) 0xa5);
        java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < 300; i++) {
            data.write(filler, 0, RANDOM.nextInt(filler.length));
            data.writeBytes(secret.getBytes(StandardCharsets.US_ASCII));
        }
        Path file = Files.write(directory.resolve("raw.bin"), data.toByteArray());
        for (int window : new int[] {64, 100, 1000, 4096, 1 << 20}) {
            List<Redactor.Region> regions = new ArrayList<>();
            long found = Redactor.find(file, Redactor.Needle.text("s", secret), regions, window);
            assertEquals(300, found, "with windows of " + window);
            assertEquals(300, regions.stream().map(Redactor.Region::position).distinct()
                    .count(), "an occurrence counted twice with windows of " + window);
        }
    }

    @Test
    void aCopyThatStillHoldsTheSecretIsRefusedAndDeleted(@TempDir Path directory)
            throws IOException {
        String secret = "left-behind-" + alnum(16);
        Path copy = Files.writeString(directory.resolve("copy.hprof"), "xx" + secret + "yy");
        Redactor.Incomplete refused = assertThrows(Redactor.Incomplete.class,
                () -> Redactor.check(copy, List.of(Redactor.Needle.text("api-key", secret)),
                        false, Set.of()));
        assertTrue(refused.getMessage().contains("api-key"), refused.getMessage());
        assertFalse(refused.getMessage().contains(secret), "the message holds the secret");
    }

    @Test
    void theCopyIsTheOwnersAloneAndNeverOverwritesAFile(@TempDir Path directory)
            throws IOException {
        Fixture f = fixture(directory, "pw-" + alnum(12), "x");
        Path out = directory.resolve("redacted.hprof");
        Redactor.redact(f.dump(), out, List.of(Redactor.Needle.text("p", f.password())),
                false, Set.of());
        try {
            assertEquals("rw-------",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(out)));
        } catch (UnsupportedOperationException notPosix) {
            // not a POSIX file system
        }
        IOException exists = assertThrows(IOException.class, () -> Redactor.redact(f.dump(),
                out, List.of(Redactor.Needle.text("p", f.password())), false, Set.of()));
        assertTrue(exists.getMessage().contains("exists already"));
        assertThrows(IllegalArgumentException.class, () -> Redactor.redact(f.dump(),
                directory.resolve("other.hprof"), List.of(), false, Set.of()));
        assertThrows(IllegalArgumentException.class, () -> Redactor.Needle.text("e", ""));
        try (var files = Files.list(directory)) {
            assertTrue(files.noneMatch(p -> p.getFileName().toString().endsWith(".part")),
                    "a partial copy was left behind");
        }
    }

    @Test
    void aDumpWithNothingFoundIsCopiedUnchanged(@TempDir Path directory) throws IOException {
        Fixture f = fixture(directory, "harmless-text", "x");
        Path out = directory.resolve("redacted.hprof");
        Redactor.Report report = Redactor.redact(f.dump(), out,
                List.of(Redactor.Needle.text("absent", "not-in-this-dump-" + alnum(8))), true,
                Set.of());
        assertFalse(report.changed());
        assertArrayEquals(Files.readAllBytes(f.dump()), Files.readAllBytes(out));
        assertEquals(Map.of("absent", 0L), report.named());
    }

    private static byte[] slice(byte[] data, long from, int length) {
        byte[] out = new byte[length];
        System.arraycopy(data, (int) from, out, 0, length);
        return out;
    }
}
