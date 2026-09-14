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
}
