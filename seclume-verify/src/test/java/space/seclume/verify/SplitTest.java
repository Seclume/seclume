package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/** {@code --split}: shares written, none printed, and they work. */
class SplitTest {

    @TempDir
    Path directory;

    @Test
    void sharesAreWrittenNotPrintedAndThreeOfFiveWork() throws Exception {
        byte[] secret = "the ring's master key, 32 bytes!".getBytes(StandardCharsets.US_ASCII);
        Path file = Files.write(directory.resolve("key"), secret);
        Path out = directory.resolve("shares");
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        int status = Split.run(List.of("file:" + file, "3", "5", out.toString()),
                new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8));
        assertEquals(0, status, stderr.toString(StandardCharsets.UTF_8));
        String printed = stdout.toString(StandardCharsets.UTF_8);
        assertTrue(printed.contains("5 shares written, any 3"), printed);
        assertFalse(printed.contains("seclume-share-1"), "a share was printed");
        assertFalse(printed.contains("master key"), "the secret was printed");

        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "shamir");
        settings.put("threshold", "3");
        int n = 1;
        for (int x : new int[] {5, 3, 1}) {
            settings.put("share." + n + ".provider", "file");
            settings.put("share." + n + ".path", out.resolve("share-" + x + "-of-5.txt").toString());
            n++;
        }
        try (SecretProvider provider = SecretProviders.of(settings);
             SecretScope scope = SecretScope.fromProvider(provider)) {
            assertArrayEquals(secret, scope.segment().asSlice(0, scope.length())
                    .toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void wrongCallsSayHow() {
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream err = new PrintStream(stderr, true, StandardCharsets.UTF_8);
        PrintStream out = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        assertEquals(2, Split.run(List.of("file:/x", "3"), out, err));
        assertEquals(2, Split.run(List.of("file:/x", "three", "5", "/tmp/x"), out, err));
        assertEquals(1, Split.run(List.of("file:" + directory.resolve("absent"), "3", "5",
                directory.resolve("s").toString()), out, err));
        assertEquals(1, Split.run(List.of("file:" + directory.resolve("absent"), "1", "5",
                directory.resolve("t").toString()), out, err));
        assertTrue(stderr.toString(StandardCharsets.UTF_8).contains("no shares written"));
    }
}
