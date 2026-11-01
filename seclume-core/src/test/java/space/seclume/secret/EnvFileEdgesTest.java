package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An env file at its edges: a file that ends inside the name or right after
 * it, a value of nothing, a value of exactly the bound, a file of exactly a
 * mebibyte, carriage returns, and a heap target. Written against the mutants
 * PIT left alive in this package.
 */
class EnvFileEdgesTest {

    @TempDir
    Path directory;

    private Path file(String content) throws IOException {
        return Files.writeString(directory.resolve("env-" + System.nanoTime()), content, StandardCharsets.US_ASCII);
    }

    private static String read(EnvFileSecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            return new String(target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.US_ASCII);
        }
    }

    private static String refusal(EnvFileSecretProvider provider) {
        return assertThrows(SecretUnavailableException.class, () -> read(provider)).getMessage();
    }

    @Test
    void aFileThatEndsInsideOrRightAfterTheNameHasNoEntry() throws IOException {
        for (String content : new String[] {"DB_PASS", "DB_PASSWORD", "DB_PASSWORD  ", "OTHER=1\nDB_PASSWORD",
                "DB_PASSWORDX=1"}) {
            Path path = file(content);
            String message = refusal(new EnvFileSecretProvider(path, "DB_PASSWORD", 64));
            assertEquals("no entry named DB_PASSWORD in " + path, message, content);
        }
    }

    @Test
    void anEmptyValueIsRefusedQuotedOrNot() throws IOException {
        for (String content : new String[] {"K=", "K=   ", "K=\"\"", "K=''", "K=\n", "K = \t"}) {
            Path path = file(content);
            assertEquals("entry K in " + path + " has an empty value",
                    refusal(new EnvFileSecretProvider(path, "K", 64)), content);
        }
    }

    @Test
    void aValueOfExactlyTheBoundFitsAndOneByteMoreDoesNot() throws IOException {
        assertEquals("abcd", read(new EnvFileSecretProvider(file("K=abcd\n"), "K", 4)));
        Path longer = file("K=abcde\n");
        assertEquals("entry K in " + longer + " is longer than the configured 4 bytes",
                refusal(new EnvFileSecretProvider(longer, "K", 4)));
        assertEquals("v", read(new EnvFileSecretProvider(file("K=v"), "K", 1)), "a bound of one byte");
    }

    @Test
    void aMaximumLengthIsPositiveAndAKeyIsNotBlank() {
        assertDoesNotThrow(() -> new EnvFileSecretProvider(directory, "K", 1));
        for (int wrong : new int[] {0, -1}) {
            assertEquals("maxLength must be positive", assertThrows(IllegalArgumentException.class,
                    () -> new EnvFileSecretProvider(directory, "K", wrong)).getMessage());
        }
        assertEquals("key must not be blank", assertThrows(IllegalArgumentException.class,
                () -> new EnvFileSecretProvider(directory, " ", 8)).getMessage());
    }

    @Test
    void aFileOfExactlyAMebibyteIsReadAndOneByteMoreIsNot() throws IOException {
        String entry = "K=found\n";
        Path exact = file("#".repeat((1 << 20) - entry.length() - 1) + "\n" + entry);
        assertEquals(1 << 20, Files.size(exact));
        assertEquals("found", read(new EnvFileSecretProvider(exact, "K", 16)));
        Path over = file("#".repeat((1 << 20) - entry.length()) + "\n" + entry);
        assertEquals((1 << 20) + 1, Files.size(over));
        assertEquals(over + " is larger than 1048576 bytes", refusal(new EnvFileSecretProvider(over, "K", 16)));
        Path empty = file("");
        assertTrue(refusal(new EnvFileSecretProvider(empty, "K", 16)).endsWith(" is empty - the file has to hold "
                + "lines of the form NAME=secret"));
    }

    @Test
    void carriageReturnsAndExportsAreNotPartOfTheValue() throws IOException {
        assertEquals("v1", read(new EnvFileSecretProvider(file("\r\nK=v1\r\nL=x\r\n"), "K", 16)));
        assertEquals("v2", read(new EnvFileSecretProvider(file("# c\r\n\r\nexport  K=v2\r\n"), "K", 16)));
        assertEquals("a b", read(new EnvFileSecretProvider(file("K=\"a b\"   \n"), "K", 16)));
        assertEquals("x", read(new EnvFileSecretProvider(file("\texport\tK=1\nK=x"), "K", 16)),
                "export takes one space, not a tab: the first line is not K");
    }

    @Test
    void aHeapTargetIsRefusedBeforeTheFileIsRead() throws IOException {
        EnvFileSecretProvider provider = new EnvFileSecretProvider(file("K=v"), "K", 8);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> provider.writeSecret(MemorySegment.ofArray(new byte[8])));
        assertTrue(e.getMessage().startsWith("seclume writes secrets only into native memory"), e.getMessage());
        assertEquals("EnvFileSecretProvider[path=" + directory.resolve("x") + ", key=DB]",
                new EnvFileSecretProvider(directory.resolve("x"), "DB", 8).toString());
    }
}
