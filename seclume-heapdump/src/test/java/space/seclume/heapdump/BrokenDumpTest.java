package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.HeapDumpScanner;

/**
 * Heap dumps arrive from outside - a support case, a volume, a ticket - and
 * every reader of them meets a broken one sooner or later: cut short, a byte
 * flipped, a length that claims gigabytes. Attribution, the redaction and the
 * scanner heapcheck uses must end such a dump in an {@link IOException}: no
 * index out of bounds, and above all no {@code OutOfMemoryError} from a
 * length taken off the file as an allocation - in the sidecar or the
 * application's own folder watch, that would be a dump that takes the
 * redaction down with it.
 */
class BrokenDumpTest {

    private static final int ROUNDS = Integer.getInteger("seclume.hprof.fuzz.rounds", 1_500);

    @TempDir
    Path directory;

    private static byte[] dump() {
        TestHprof h = new TestHprof(8);
        h.loadClass(0x100, "java/lang/String");
        h.byteArray(0x500, "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
                .getBytes(StandardCharsets.US_ASCII), new long[1]);
        h.objectArray(0x600, 0x100, 0x500, 0x500);
        h.finish();
        h.end();
        return h.file.toByteArray();
    }

    /** A string record that claims 2 GB: once an allocation, now a broken dump. */
    @Test
    void aLengthBeyondTheFileIsABrokenDumpNotAnAllocation() throws IOException {
        TestHprof h = new TestHprof(8);
        h.file.write(0x01);                                   // STRING IN UTF8
        TestHprof.u4(h.file, 0);
        TestHprof.u4(h.file, 0x7ffffff0L);
        TestHprof.u8(h.file, 0x1000);
        byte[] text = "a secret abcdefgh in a record that is not there".getBytes(
                StandardCharsets.US_ASCII);
        h.file.write(text, 0, text.length);
        Path file = Files.write(directory.resolve("claims.hprof"), h.file.toByteArray());
        assertThrows(IOException.class, () -> Attribution.analyse(file, new long[] {40}));
        assertThrows(IOException.class, () -> Redactor.redact(file,
                directory.resolve("claims.redacted.hprof"),
                List.of(Redactor.Needle.text("x", "abcdefgh")), false, Set.of()));
        assertFalse(Files.exists(directory.resolve("claims.redacted.hprof")));
    }

    @Test
    void mutatedDumpsEndInAResultOrAnIoException() throws IOException {
        byte[] base = dump();
        Random random = new Random(Long.getLong("seclume.hprof.fuzz.seed", 20261030L));
        Path file = directory.resolve("mutated.hprof");
        for (int round = 0; round < ROUNDS; round++) {
            byte[] mutated = base.clone();
            for (int i = 0; i < 1 + random.nextInt(4) && mutated.length > 0; i++) {
                int at = random.nextInt(mutated.length);
                switch (random.nextInt(3)) {
                    case 0 -> mutated[at] = (byte) random.nextInt(256);
                    case 1 -> mutated[at] = (byte) 0xff;
                    default -> mutated = Arrays.copyOf(mutated, at);
                }
            }
            Files.write(file, mutated);
            Path out = directory.resolve("out-" + round + ".hprof");
            try {
                try {
                    Attribution.analyse(file, new long[] {mutated.length / 2});
                } catch (IOException broken) {
                    // said as such
                }
                try {
                    Redactor.redact(file, out, List.of(), true, Set.of());
                } catch (IOException broken) {
                    // said as such
                }
                try {
                    HeapDumpScanner.scan(file, "ghp_abcdefghijklmnopqrstuvwxyz0123456789");
                } catch (IOException broken) {
                    // said as such
                }
                try {
                    HeapDumpScanner.scanBytes(file, new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
                } catch (IOException broken) {
                    // said as such
                }
            } catch (RuntimeException | OutOfMemoryError e) {
                throw new AssertionError("round " + round + ": " + e, e);
            } finally {
                Files.deleteIfExists(out);
            }
        }
    }
}
