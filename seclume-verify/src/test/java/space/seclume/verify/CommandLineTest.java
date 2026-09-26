package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.tck.ChildJvm;

/**
 * The exit code, because that is the whole contract in a pipeline.
 *
 * <p>Nobody reads this tool's output in a build. A pipeline runs it and looks at
 * one number, so the number is the feature: <b>0</b> the connection stands,
 * <b>1</b> it does not, <b>2</b> the tool was called wrongly. The other tests
 * here check what the report says; none of them ever ran {@code main}, and
 * {@code main} is the part that maps everything onto that number.
 *
 * <p>In a child process, because {@code main} ends in {@code System.exit} - in
 * this JVM that would take the test run with it.
 */
class CommandLineTest {

    /** Called without a URL: say how, and do not pretend to have checked anything. */
    @Test
    void withoutAUrlItExplainsItselfAndFailsAsAMisuse() throws Exception {
        ChildJvm.Result result = ChildJvm.run(Verify.class, List.of(), 60);
        assertEquals(2, result.exitCode(), result.output());
        assertTrue(result.output().contains("usage:"), result.output());
    }

    /**
     * A URL of somebody else's driver: a failure, never a pass.
     *
     * <p>This is the one that matters. A pipeline that runs the tool against a
     * URL no seclume driver accepts must go red - reporting "no driver" and
     * exiting 0 would mean the build passes while nothing at all was verified.
     */
    @Test
    void aUrlThatIsNotOursFails() throws Exception {
        ChildJvm.Result result = ChildJvm.run(Verify.class,
                List.of("jdbc:postgresql://host/db"), 60);
        assertEquals(1, result.exitCode(),
                "a URL we cannot even take must not come back as success: " + result.output());
    }

    /** And a server that is not there is a failure too, with the reason. */
    @Test
    void aServerThatIsNotThereFails() throws Exception {
        ChildJvm.Result result = ChildJvm.run(Verify.class,
                List.of("jdbc:seclume:postgresql://127.0.0.1:1/db"
                        + "?user=nobody&provider=file&path=does-not-exist"),
                60);
        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains("what to do"),
                "a failure without advice sends somebody guessing: " + result.output());
    }

    /**
     * {@code --json}: one document on stdout, and nothing else.
     *
     * <p>The "nothing else" is the assertion. A probe pipes this straight into
     * a parser, so a single line of prose in front of the brace - a warning, a
     * banner, an "opening connection..." - breaks it, and breaks it in the
     * environment where nobody is watching.
     */
    @Test
    void jsonPrintsADocumentAndNothingElse() throws Exception {
        ChildJvm.Result result = ChildJvm.run(Verify.class,
                List.of("--json", "jdbc:postgresql://host/db"), 60);
        assertEquals(1, result.exitCode(), result.output());
        String out = result.output().strip();
        assertTrue(out.startsWith("{") && out.endsWith("}"),
                "something else got printed beside the document: " + out);
        assertTrue(out.contains("\"ok\": false"), out);
        assertTrue(out.contains("\"status\": 1"), out);
    }

    /** The flag on its own is still a misuse, and still exit 2. */
    @Test
    void jsonWithoutAUrlIsStillAMisuse() throws Exception {
        ChildJvm.Result result = ChildJvm.run(Verify.class, List.of("--json"), 60);
        assertEquals(2, result.exitCode(), result.output());
        assertTrue(result.output().contains("usage:"), result.output());
    }
}
