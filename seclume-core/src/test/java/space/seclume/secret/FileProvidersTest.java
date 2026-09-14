package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.Segments;

/** The file and .env providers: the two routes most common in production. */
class FileProvidersTest {

    @TempDir
    Path directory;

    @Test
    void readsAFile() throws IOException {
        Path file = write("secret.txt", "s3cr3t");
        assertEquals("s3cr3t", read(new FileSecretProvider(file, 64)));
    }

    /** {@code echo secret > file} appends a line ending - that has to go. */
    @Test
    void trimsTrailingNewline() throws IOException {
        assertEquals("s3cr3t", read(new FileSecretProvider(write("unix.txt", "s3cr3t\n"), 64)));
        assertEquals("s3cr3t", read(new FileSecretProvider(write("dos.txt", "s3cr3t\r\n"), 64)));
    }

    @Test
    void keepsInnerWhitespace() throws IOException {
        assertEquals("two words", read(new FileSecretProvider(write("ws.txt", "two words\n"), 64)));
    }

    @Test
    void rejectsSecretsThatDoNotFit() throws IOException {
        Path file = write("long.txt", "0123456789abcdef");
        SecretUnavailableException failure = assertThrows(SecretUnavailableException.class,
                () -> read(new FileSecretProvider(file, 8)));
        assertTrue(failure.getMessage().contains("longer than"));
    }

    @Test
    void rejectsAnEmptyFile() throws IOException {
        Path file = write("empty.txt", "\n");
        assertThrows(SecretUnavailableException.class, () -> read(new FileSecretProvider(file, 8)));
    }

    @Test
    void reportsAMissingFileWithItsPath() {
        Path file = directory.resolve("absent.txt");
        SecretUnavailableException failure = assertThrows(SecretUnavailableException.class,
                () -> read(new FileSecretProvider(file, 8)));
        assertTrue(failure.getMessage().contains("absent.txt"));
    }

    /** A heap segment as the target would silently defeat the core property. */
    @Test
    void refusesHeapTargets() throws IOException {
        Path file = write("heap.txt", "s3cr3t");
        MemorySegment heap = MemorySegment.ofArray(new byte[64]);
        assertThrows(IllegalArgumentException.class,
                () -> new FileSecretProvider(file, 64).writeSecret(heap));
    }

    @Test
    void readsAnEnvFileEntry() throws IOException {
        Path file = write(".env", """
                # a comment
                OTHER=irrelevant
                DB_PASSWORD=s3cr3t
                TRAILING=x
                """);
        assertEquals("s3cr3t", read(new EnvFileSecretProvider(file, "DB_PASSWORD", 64)));
    }

    @Test
    void handlesQuotesExportAndSpaces() throws IOException {
        Path file = write("quoted.env", """
                export DB_PASSWORD = "with spaces and = sign"
                SINGLE='single quoted'
                """);
        assertEquals("with spaces and = sign",
                read(new EnvFileSecretProvider(file, "DB_PASSWORD", 64)));
        assertEquals("single quoted", read(new EnvFileSecretProvider(file, "SINGLE", 64)));
    }

    /** A key that is only a prefix must not match. */
    @Test
    void doesNotMatchAPrefix() throws IOException {
        Path file = write("prefix.env", "DB_PASSWORD_OLD=wrong\nDB_PASSWORD=right\n");
        assertEquals("right", read(new EnvFileSecretProvider(file, "DB_PASSWORD", 64)));
    }

    @Test
    void reportsAMissingEntry() throws IOException {
        Path file = write("missing.env", "SOMETHING=else\n");
        SecretUnavailableException failure = assertThrows(SecretUnavailableException.class,
                () -> read(new EnvFileSecretProvider(file, "DB_PASSWORD", 64)));
        assertTrue(failure.getMessage().contains("DB_PASSWORD"));
    }

    private Path write(String name, String content) throws IOException {
        Path file = directory.resolve(name);
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file;
    }

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined();
             SecretScope scope = SecretScope.fromProvider(provider)) {
            byte[] copy = Segments.toBytes(scope.secret());
            assertTrue(arena.scope().isAlive());
            return new String(copy, StandardCharsets.UTF_8);
        }
    }
}
