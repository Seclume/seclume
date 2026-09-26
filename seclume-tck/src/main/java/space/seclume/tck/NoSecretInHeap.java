package space.seclume.tck;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Proves, for <b>your</b> application, that its database password is not on
 * the heap.
 *
 * <pre>
 * &#64;ExtendWith(NoSecretInHeap.class)
 * class ApplicationTest {
 *     &#64;Test void startsUpAndQueries() { ... }
 * }
 * </pre>
 *
 * <p>Point it at the <b>file</b> that holds the password, with the system
 * property {@code seclume.tck.secret-file}:
 *
 * <pre>mvn test -Dseclume.tck.secret-file=/run/secrets/db</pre>
 *
 * <p>After every test the extension dumps this JVM's heap, hands the dump and
 * the path to a <b>separate process</b> that does the searching, and fails the
 * test if that process finds the secret.
 *
 * <p><b>Why a separate process, and why a file.</b> Searching needs the secret
 * as a pattern, and a pattern is a {@code String}. Naming the secret in a
 * system property or an environment variable - which is what this extension
 * used to ask for - puts it into the heap of the very process being examined:
 * the check then finds its own configuration and fails on an application that
 * is perfectly clean. That is not a corner case, it happens on the first run,
 * and a test in this module pins it down. So the test JVM only ever holds the
 * <i>path</i>, and the pattern lives in the child.
 *
 * <p><b>Why this ships with the library.</b> A driver that keeps no password
 * on the heap is a claim, and claims about security are worth what their proof
 * is worth. This is the proof - and it does not stop at the driver: the
 * password usually reaches the heap through the application anyway, in a
 * configuration object, a log line, a {@code toString()} of a data source, an
 * exception message. Those are found here too, and they are the ones nobody
 * looks for.
 *
 * <p>It searches both raw and structured: the bytes as they lie in the dump,
 * and the strings the parser reconstructs. A hit reports where it was found,
 * never the value.
 */
public final class NoSecretInHeap implements AfterEachCallback {

    /** The file holding the secret to look for - a path, never the value. */
    public static final String SECRET_FILE_PROPERTY = "seclume.tck.secret-file";
    /** The old way of saying it, which cannot work - see the class comment. */
    public static final String SECRET_PROPERTY = "seclume.tck.secret";
    /** The same through the environment, and broken for the same reason. */
    public static final String SECRET_VARIABLE = "SECLUME_TCK_SECRET";

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        Path secretFile = secretFile();
        if (secretFile == null) {
            throw new IllegalStateException(
                    "NoSecretInHeap does not know what to look for - set the system property "
                    + SECRET_FILE_PROPERTY + " to the file holding the password this test "
                    + "uses. A check that passes without looking would be worse than no "
                    + "check.");
        }
        if (!Files.isReadable(secretFile)) {
            throw new IllegalStateException(SECRET_FILE_PROPERTY + " points at "
                    + secretFile + ", which cannot be read - without the secret there is "
                    + "nothing to look for.");
        }
        check(secretFile, "after " + context.getDisplayName());
    }

    /**
     * The same check at a moment of the test's choosing - right after the
     * login, between two steps, before the connection is closed - rather than
     * only after the test.
     *
     * <pre>
     *   dataSource.getConnection().close();
     *   NoSecretInHeap.assertAbsent(Path.of("/run/secrets/db"));
     * </pre>
     *
     * @param secretFile the file holding the secret - never the secret itself,
     *                   see the class comment for why
     * @throws AssertionError when the secret is on the heap, saying where
     */
    public static void assertAbsent(Path secretFile) throws IOException, InterruptedException {
        if (!Files.isReadable(secretFile)) {
            throw new IllegalStateException(secretFile + " cannot be read - without the "
                    + "secret there is nothing to look for.");
        }
        check(secretFile, "at this point");
    }

    private static void check(Path secretFile, String when)
            throws IOException, InterruptedException {
        Path dump = Files.createTempFile("seclume-heap-", ".hprof");
        Files.delete(dump);                      // the JVM insists on writing it itself
        try {
            Heap.collect();
            Heap.dump(dump);
            // The search happens in a process of its own: it needs the secret
            // as a pattern, and a pattern here would be a String on the heap
            // that was just dumped.
            ChildJvm.Result result = ChildJvm.run(ScanDump.class,
                    List.of(dump.toString(), secretFile.toString()), 120);
            if (result.exitCode() == 1) {
                throw new AssertionError(message(when, result.output()));
            }
            if (result.exitCode() != 0) {
                throw new IllegalStateException("the heap search did not run: "
                        + result.output());
            }
        } finally {
            deleteQuietly(dump);
        }
    }

    private static String message(String when, String findings) {
        StringBuilder text = new StringBuilder(); // seclume-allow: a test report, the secret itself is never in it
        text.append("the secret is on the heap ")
                .append(when)
                .append(":\n").append(findings.strip());
        text.append("\n\nWhere it usually comes from: a configuration object that keeps it "
                + "as a String, a log line, the toString() of a data source, or an exception "
                + "message. The driver does not put it there.");
        return text.toString();
    }

    /**
     * The file to read the secret from.
     *
     * <p>The two older ways of naming it are refused rather than honoured: a
     * value in a property or in the environment is on the heap by the time the
     * search starts, and the result would say more about the configuration
     * than about the application.
     */
    private static Path secretFile() {
        String file = System.getProperty(SECRET_FILE_PROPERTY);
        if (file != null && !file.isEmpty()) {
            return Path.of(file);
        }
        if (System.getProperty(SECRET_PROPERTY) != null
                || System.getenv(SECRET_VARIABLE) != null) { // seclume-allow: only asked whether it is set, the value is never read
            throw new IllegalStateException(
                    SECRET_PROPERTY + " and " + SECRET_VARIABLE + " cannot work: a secret "
                    + "named that way is a String on the heap of this very process, so the "
                    + "check would find its own configuration and fail on an application "
                    + "that is clean. Use " + SECRET_FILE_PROPERTY + " and point it at the "
                    + "file the application reads.");
        }
        return null;
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // A leftover dump in the temporary directory is not worth failing
            // a test that has already answered its question.
        }
    }
}
