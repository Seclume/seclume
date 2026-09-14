package space.seclume.tck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The proof of the core property.
 *
 * <p>The setup: a second JVM uses a distinctive random password the way a
 * driver would, and then writes out its heap. The test searches the file raw
 * and structured.
 *
 * <p>The <b>negative control</b> is the more important part: the same procedure
 * with a deliberately leaking provider has to find the password. A green run
 * without it would only mean that something found nothing.
 */
class HeapDumpTest {

    @TempDir
    Path directory;

    /** The actual proof: with SecretScope nothing is left behind on the heap. */
    @Test
    void offHeapPathLeavesNoTrace() throws Exception {
        String secret = randomSecret();
        Path dump = runProbe("offheap", secret, 5);

        List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
        assertTrue(findings.isEmpty(),
                "the secret is in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }

    /**
     * The negative control. Without this run the one above proves nothing: a
     * broken search finds nothing either.
     */
    @Test
    void leakingProviderIsFound() throws Exception {
        String secret = randomSecret();
        Path dump = runProbe("leaking", secret, 1);

        List<HeapDumpScanner.Finding> raw = HeapDumpScanner.scanRaw(dump, secret);
        List<HeapDumpScanner.Finding> structured = HeapDumpScanner.scanStructured(dump, secret);

        assertFalse(raw.isEmpty(), "the raw scan must find a secret that is really there");
        assertFalse(structured.isEmpty(),
                "the structured scan must find a secret that is really there");
    }

    /**
     * The hardest case: the dump is taken while the secret is in use.
     * Off-heap memory appears in no hprof - showing exactly that is the point
     * here, since otherwise the core property would be a mere question of the
     * right
     * Augenblicks.
     */
    @Test
    void nothingIsVisibleWhileTheSecretIsInUse() throws Exception {
        String secret = randomSecret();
        Path dump = runProbe("offheap-open", secret, 1);
        assertTrue(HeapDumpScanner.scan(dump, secret).isEmpty(),
                "the secret showed up while a scope was open");
    }

    /**
     * After several cycles and a full GC nothing may be left either - that is
     * the case a pool with reconnects produces.
     */
    @Test
    void nothingSurvivesManyCycles() throws Exception {
        String secret = randomSecret();
        Path dump = runProbe("offheap", secret, 50);
        assertTrue(HeapDumpScanner.scan(dump, secret).isEmpty(),
                "the secret survived a series of reconnects");
    }

    /** The parser has to read the whole dump, or every statement is worthless. */
    @Test
    void parserReadsTheWholeDump() throws Exception {
        String secret = randomSecret();
        Path dump = runProbe("offheap", secret, 1);

        assertTrue(HprofParser.formatName(dump).startsWith("JAVA PROFILE"));
        int[] arrays = {0};
        long[] bytes = {0};
        HprofParser.forEachPrimitiveArray(dump, (id, type, data) -> {
            arrays[0]++;
            bytes[0] += data.remaining();
        });
        // There is no JVM without byte[] and char[]; if the parser finds none
        // it is running into the void, and the green test would be a lie.
        assertTrue(arrays[0] > 100, "only " + arrays[0] + " primitive arrays found");
        assertTrue(bytes[0] > 100_000, "only " + bytes[0] + " bytes of array data found");
    }

    /** Starts the probe and returns the dump it wrote. */
    private Path runProbe(String mode, String secret, int cycles) throws Exception {
        Path secretFile = directory.resolve(mode + "-secret.txt");
        Path dump = directory.resolve(mode + "-" + cycles + ".hprof");
        Files.writeString(secretFile, secret, StandardCharsets.UTF_8);

        ChildJvm.Result result = ChildJvm.run(SecretHolderProbe.class,
                List.of(mode, secretFile.toString(), dump.toString(), String.valueOf(cycles)),
                180);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(Files.exists(dump), "no heap dump was written:\n" + result.output());

        // The file holding the password must no longer exist while searching -
        // it sits in the same directory as the dump.
        Files.delete(secretFile);
        return dump;
    }

    /**
     * A password that occurs nowhere else. Random, so that no leftover from an
     * earlier run turns the test green, and in hex so that it survives in
     * every
     * encoding unambiguously.
     */
    private static String randomSecret() {
        byte[] random = new byte[12];
        new SecureRandom().nextBytes(random);
        return "zLk" + HexFormat.of().formatHex(random) + "Zz";
    }
}
