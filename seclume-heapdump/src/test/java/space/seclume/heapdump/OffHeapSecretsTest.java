package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.NoSecretInHeap;

/**
 * A redaction that looks for the application's own secrets - held in native
 * memory - finds and overwrites their copies in a dump without making one on
 * the heap: the patterns are built in native memory, the dump is searched in
 * native windows, and the heap proof says so afterwards.
 */
class OffHeapSecretsTest {

    private static MemorySegment nativeCopy(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static byte[] bytes(MemorySegment segment) {
        return segment.toArray(ValueLayout.JAVA_BYTE);
    }

    /** The encodings made in native memory are the JDK's, byte for byte - on text that is no secret. */
    @Test
    void theNativeEncodingsAreTheJdks() {
        for (String text : List.of("a", "ab", "abc", "pässwörd", "日本語", "emoji 🔑 key",
                "x".repeat(1000))) {
            try (Arena arena = Arena.ofConfined()) {
                OffHeapSecrets.Needle needle = OffHeapSecrets.text("t",
                        nativeCopy(arena, text.getBytes(StandardCharsets.UTF_8)), arena);
                assertEquals(4, needle.patterns().size(), text);
                assertArrayEquals(text.getBytes(StandardCharsets.UTF_16BE),
                        bytes(needle.patterns().get(1).bytes()), text);
                assertArrayEquals(text.getBytes(StandardCharsets.UTF_16LE),
                        bytes(needle.patterns().get(2).bytes()), text);
                assertArrayEquals(Base64.getEncoder().encode(text.getBytes(StandardCharsets.UTF_8)),
                        bytes(needle.patterns().get(3).bytes()), text);
            }
        }
        try (Arena arena = Arena.ofConfined()) {
            // Not UTF-8: looked for as bytes.
            OffHeapSecrets.Needle binary = OffHeapSecrets.text("k",
                    nativeCopy(arena, new byte[] {(byte) 0xff, 1, 2}), arena);
            assertEquals(List.of("bytes", "Base64"),
                    binary.patterns().stream().map(OffHeapSecrets.Pattern::encoding).toList());
        }
    }

    @Test
    void aSecretKeptOffTheHeapIsRedactedWithoutACopyOnIt(@TempDir Path directory)
            throws Exception {
        // The secret is made by a process of its own and read into native
        // memory only: this JVM never holds it in an array or a String.
        Path secretFile = directory.resolve("api-key");
        Process openssl = new ProcessBuilder("openssl", "rand", "-hex", "-out",
                secretFile.toString(), "16").redirectErrorStream(true).start();
        assertTrue(openssl.waitFor(30, TimeUnit.SECONDS) && openssl.exitValue() == 0);
        long length = Files.size(secretFile) - 1;                // without the newline

        // A dump whose byte[] holds the secret: written with a placeholder,
        // the secret copied over it by the file system.
        TestHprof h = new TestHprof(8);
        long[] at = new long[1];
        long first = h.byteArray(0x500, new byte[(int) length], at);
        long second = h.byteArray(0x501, new byte[(int) length], at);
        long segment = h.finish();
        Path dump = Files.write(directory.resolve("app.hprof"), h.file.toByteArray());
        try (FileChannel from = FileChannel.open(secretFile, StandardOpenOption.READ);
             FileChannel to = FileChannel.open(dump, StandardOpenOption.WRITE)) {
            for (long where : new long[] {segment + first, segment + second}) {
                long copied = 0;
                while (copied < length) {
                    copied += from.transferTo(copied, length - copied, to.position(where + copied));
                }
            }
        }

        OffHeapSecrets secrets = () -> {
            Arena arena = Arena.ofShared();
            MemorySegment secret = arena.allocate(length);
            try (FileChannel in = FileChannel.open(secretFile, StandardOpenOption.READ)) {
                in.read(secret.asByteBuffer(), 0);
            } catch (IOException e) {
                arena.close();
                throw new IllegalStateException(e);
            }
            List<OffHeapSecrets.Needle> needles =
                    List.of(OffHeapSecrets.text("api-key", secret, arena));
            return new OffHeapSecrets.Opened() {
                @Override
                public List<OffHeapSecrets.Needle> needles() {
                    return needles;
                }

                @Override
                public void close() {
                    secret.fill((byte) 0);
                    arena.close();
                }
            };
        };

        Path out = directory.resolve("redacted.hprof");
        Redactor.Report report = Redactor.redact(dump, out, List.of(), secrets, false, Set.of());
        assertEquals(2L, report.named().get("api-key"));

        // Nothing left in the copy, by the same native search - in windows of
        // every size, so that a match across a window's edge would show.
        try (OffHeapSecrets.Opened opened = secrets.open()) {
            for (int window : new int[] {16, 33, 64, 1 << 20}) {
                assertEquals(2, Redactor.find(dump, opened.needles().get(0), new ArrayList<>(),
                        window), "the original, in windows of " + window);
                assertEquals(0, Redactor.find(out, opened.needles().get(0), new ArrayList<>(),
                        window), "the copy, in windows of " + window);
            }
        }
        NoSecretInHeap.assertAbsent(secretFile);
    }
}
