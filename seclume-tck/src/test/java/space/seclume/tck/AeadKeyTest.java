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
 * The measurement that decides how TLS 1.3 gets its AEAD.
 *
 * <p>{@code docs/tls.md} leaves one question open, and everything above the
 * record layer depends on the answer: TLS 1.3 needs AES-GCM, this project's own
 * AES has none, and the choice is between writing GHASH - where a
 * data-dependent branch is a timing side channel nobody here would find by
 * testing - and letting the JCA do it. The argument against the JCA is that it
 * puts the traffic key on the heap. This turns that argument into a dump.
 *
 * <p>Both directions are run, because a finding without its control says
 * nothing. If the key were findable either way the experiment would be
 * measuring the harness; if it were findable neither way the search would be
 * broken.
 */
class AeadKeyTest {

    @TempDir
    Path directory;

    /**
     * Through the JCA the key is on the heap, and cannot be got off it.
     *
     * <p>{@code Cipher.init} takes a {@code SecretKey}; every implementation of
     * that hands its bytes out as a heap array, and {@code SecretKeySpec} keeps
     * a copy for as long as it lives. It does not implement {@code destroy()} -
     * the default throws - so there is no wiping it either. The probe zeroes
     * its own array before the dump, so what is found is the copy inside the
     * JCA and not the one the probe made.
     */
    @Test
    void theJcaLeavesTheTrafficKeyOnTheHeap() throws Exception {
        String key = randomKey();
        Path dump = runProbe("jca", key);
        List<HeapDumpScanner.Finding> found = HeapDumpScanner.scan(dump, key);
        assertFalse(found.isEmpty(),
                "expected the JCA to leave the key on the heap - if this is empty, the "
                        + "search is broken and every other heap test in this project is worthless");
    }

    /** Through our own AES it is not there at all. */
    @Test
    void ourOwnAesLeavesNothing() throws Exception {
        String key = randomKey();
        Path dump = runProbe("ours", key);
        List<HeapDumpScanner.Finding> found = HeapDumpScanner.scan(dump, key);
        assertTrue(found.isEmpty(), "the key was found " + found.size() + " times: " + found);
    }

    private Path runProbe(String mode, String key) throws Exception {
        Path keyFile = directory.resolve(mode + "-key.txt");
        Path dump = directory.resolve(mode + ".hprof");
        Files.writeString(keyFile, key, StandardCharsets.UTF_8);

        ChildJvm.Result result = ChildJvm.run(AeadKeyProbe.class,
                List.of(mode, keyFile.toString(), dump.toString()), 180);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(Files.exists(dump), "no heap dump was written:\n" + result.output());

        // The file must be gone before the search; it sits next to the dump.
        Files.delete(keyFile);
        return dump;
    }

    /**
     * Thirty-two printable characters - a valid AES-256 key and searchable as
     * text.
     *
     * <p>Random, so that a leftover from an earlier run cannot turn the second
     * test green.
     */
    private static String randomKey() {
        byte[] random = new byte[14];
        new SecureRandom().nextBytes(random);
        return "zLkAead" + HexFormat.of().formatHex(random).substring(0, 25);
    }
}
