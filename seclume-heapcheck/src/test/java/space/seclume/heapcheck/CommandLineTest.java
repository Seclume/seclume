package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.tck.ChildJvm;

/**
 * The exit code, because that is the whole contract in a pipeline.
 *
 * <p>0 nothing found, 1 the secret is in the heap, 2 the check could not run -
 * and the difference between the last two is the entire point of the tool. A
 * check that cannot run and says 0 reports a clean heap it never looked at.
 * {@link HeapCheckTest} proves the searching; this proves the calling, which no
 * test touched before.
 *
 * <p>In a child process, because {@code main} ends in {@code System.exit}.
 */
class CommandLineTest {

    @Test
    void withoutArgumentsItExplainsItselfAndFailsAsAMisuse() throws Exception {
        ChildJvm.Result result = ChildJvm.run(HeapCheck.class, List.of(), 60);
        assertEquals(2, result.exitCode(), result.output());
        assertTrue(result.output().contains("usage:"), result.output());
    }

    /** Naming the secret itself is refused - arguments are public on this machine. */
    @Test
    void aSecretAsAnArgumentIsNotAccepted() throws Exception {
        ChildJvm.Result result = ChildJvm.run(HeapCheck.class,
                List.of("--pid", "1", "--secret", "hunter2"), 60);
        assertEquals(2, result.exitCode(),
                "a secret on the command line must not be taken: " + result.output());
        assertTrue(result.output().contains("visible to every process"),
                "the refusal has to say why, or it reads as a missing feature: "
                + result.output());
    }

    /** A process that is not there cannot be examined - and must not look clean. */
    @Test
    void aProcessThatIsNotThereIsAFailureNotACleanHeap() throws Exception {
        ChildJvm.Result result = ChildJvm.run(HeapCheck.class,
                List.of("--pid", "999999999", "--secret-file", "does-not-exist"), 60);
        assertEquals(2, result.exitCode(),
                "a check that could not run reported a clean heap: " + result.output());
    }

    /** A dump and a process at once is a misuse, not a guess at which was meant. */
    @Test
    void aDumpAndAProcessTogetherAreRefused() throws Exception {
        ChildJvm.Result result = ChildJvm.run(HeapCheck.class,
                List.of("--pid", "1", "--dump", "x.hprof", "--secret-file", "s"), 60);
        assertEquals(2, result.exitCode(), result.output());
        assertTrue(result.output().contains("one of them"), result.output());
    }

    /** A dump that is not there is a failure, not a clean heap. */
    @Test
    void aDumpThatIsNotThereIsAFailure(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir)
            throws Exception {
        java.nio.file.Path secret = dir.resolve("s");
        java.nio.file.Files.writeString(secret, "some-secret-value");
        ChildJvm.Result result = ChildJvm.run(HeapCheck.class,
                List.of("--dump", dir.resolve("missing.hprof").toString(), "--secret-file",
                        secret.toString()), 60);
        assertEquals(2, result.exitCode(), result.output());
    }

    @Test
    void theDetectorsCanBeListed() throws Exception {
        ChildJvm.Result result = ChildJvm.run(HeapCheck.class, List.of("--list-detectors"), 60);
        assertEquals(0, result.exitCode(), result.output());
        for (String id : Discovery.ids()) {
            assertTrue(result.output().contains(id), id + " missing: " + result.output());
        }
    }

    /** --discover alone is a check; a detector that does not exist is a typo, not a filter. */
    @Test
    void discoverAloneRunsAndAnUnknownDetectorIsRefused(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path dump = dir.resolve("app.hprof");
        java.nio.file.Files.writeString(dump, "\u0001\u0002 nothing like a credential \u0003");
        ChildJvm.Result clean = ChildJvm.run(HeapCheck.class,
                List.of("--dump", dump.toString(), "--discover"), 60);
        assertEquals(0, clean.exitCode(), clean.output());
        assertTrue(clean.output().contains("DISCOVERED nothing"), clean.output());

        // Made up here rather than written down: a token-shaped literal in the
        // repository is what secret scanning is there to stop.
        byte[] random = new byte[24];
        new java.security.SecureRandom().nextBytes(random);
        String body = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        java.nio.file.Files.writeString(dump, "\u0001 hvs." + body + " \u0002");
        ChildJvm.Result found = ChildJvm.run(HeapCheck.class,
                List.of("--dump", dump.toString(), "--discover"), 60);
        assertEquals(1, found.exitCode(), found.output());
        assertTrue(found.output().contains("`vault-token`"), found.output());
        assertTrue(!found.output().contains(body.substring(0, 16)),
                "the value was printed: " + found.output());

        ChildJvm.Result ignored = ChildJvm.run(HeapCheck.class,
                List.of("--dump", dump.toString(), "--discover", "--ignore", "vault-token"), 60);
        assertEquals(0, ignored.exitCode(), ignored.output());

        ChildJvm.Result typo = ChildJvm.run(HeapCheck.class,
                List.of("--dump", dump.toString(), "--discover", "--ignore", "vault-tokens"), 60);
        assertEquals(2, typo.exitCode(), typo.output());
        assertTrue(typo.output().contains("no such detector"), typo.output());

        ChildJvm.Result withoutDiscover = ChildJvm.run(HeapCheck.class,
                List.of("--dump", dump.toString(), "--ignore", "jwt"), 60);
        assertEquals(2, withoutDiscover.exitCode(), withoutDiscover.output());
    }
}
