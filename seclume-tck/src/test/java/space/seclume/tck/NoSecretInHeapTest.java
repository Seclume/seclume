package space.seclume.tck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;

/**
 * The extension applied to itself - and that turned out to be the hard part.
 *
 * <p>It shipped as a tool for other people's projects and was never exercised
 * here, which is how this stayed unnoticed: the secret used to be named through
 * a system property, and a system property <b>is a {@code String} on the heap
 * of the very process being examined</b>. The check found its own configuration
 * and failed - on an application that is perfectly clean.
 *
 * <p>The same trap catches the test one level up. A test that writes the secret
 * as a literal in its own source has it in the constant pool, so its JVM is
 * never clean either. So the two interesting cases run in <b>child processes</b>:
 * one that only knows the path, one that reads the file into a {@code String} -
 * which is what almost every application does. Even the secret itself is made
 * of random bytes and written without ever becoming a {@code String} here.
 */
class NoSecretInHeapTest {

    /** A clean process: it knows the path and never looks inside. */
    @Test
    void aCleanProcessComesBackClean(@TempDir Path directory) throws Exception {
        Path secretFile = writeSecret(directory);
        ChildJvm.Result result = ChildJvm.run(CleanProbe.class,
                List.of(secretFile.toString()), 180);
        assertEquals(0, result.exitCode(),
                "a process that never held the secret was reported as leaking: "
                + result.output());
    }

    /** And one that does what everybody does - otherwise the first proves nothing. */
    @Test
    void aSecretOnTheHeapIsFound(@TempDir Path directory) throws Exception {
        Path secretFile = writeSecret(directory);
        ChildJvm.Result result = ChildJvm.run(LeakingProbe.class,
                List.of(secretFile.toString()), 180);
        assertEquals(1, result.exitCode(),
                "the secret was on that heap and the check did not find it: "
                + result.output());
        assertTrue(result.output().contains("on the heap"), result.output());
    }

    /** The same check called in the middle of a test: clean passes, a leak is found. */
    @Test
    void theCheckCanBeCalledWhenTheTestWantsIt(@TempDir Path directory) throws Exception {
        Path secretFile = writeSecret(directory);
        ChildJvm.Result clean = ChildJvm.run(AssertAbsentProbe.class,
                List.of(secretFile.toString(), "clean"), 180);
        assertEquals(0, clean.exitCode(), clean.output());
        ChildJvm.Result leaking = ChildJvm.run(AssertAbsentProbe.class,
                List.of(secretFile.toString(), "leak"), 180);
        assertEquals(1, leaking.exitCode(), leaking.output());
        assertTrue(leaking.output().contains("on the heap at this point"), leaking.output());
    }

    /** The old way is refused, and the message says why it cannot work. */
    @Test
    void namingTheSecretInAPropertyIsRefused() {
        String before = System.getProperty(NoSecretInHeap.SECRET_PROPERTY);
        System.setProperty(NoSecretInHeap.SECRET_PROPERTY, "does-not-matter");
        try {
            IllegalStateException thrown = assertThrows(IllegalStateException.class,
                    () -> new NoSecretInHeap().afterEach(context()));
            assertTrue(thrown.getMessage().contains("String on the heap"),
                    thrown.getMessage());
        } finally {
            if (before == null) {
                System.clearProperty(NoSecretInHeap.SECRET_PROPERTY);
            } else {
                System.setProperty(NoSecretInHeap.SECRET_PROPERTY, before);
            }
        }
    }

    /** Without anything configured it refuses rather than passing quietly. */
    @Test
    void withoutASecretItRefusesToRun() {
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> new NoSecretInHeap().afterEach(context()));
        assertTrue(thrown.getMessage().contains("does not know what to look for"),
                thrown.getMessage());
    }

    /**
     * A random secret, written without ever being a {@code String} here.
     *
     * <p>Hex digits, built as bytes: a literal in this class would sit in the
     * constant pool, and this JVM would then never be clean.
     */
    private static Path writeSecret(Path directory) throws Exception {
        byte[] random = new byte[16]; // seclume-allow: random bytes on their way to a file, no secret of anybody's
        new SecureRandom().nextBytes(random);
        byte[] hex = new byte[random.length * 2]; // seclume-allow: the same bytes as text
        for (int i = 0; i < random.length; i++) {
            hex[i * 2] = digit((random[i] >> 4) & 0xf);
            hex[i * 2 + 1] = digit(random[i] & 0xf);
        }
        Path file = directory.resolve("secret");
        Files.write(file, hex);
        return file;
    }

    private static byte digit(int value) {
        return (byte) (value < 10 ? '0' + value : 'a' + value - 10);
    }

    /** The little that the extension actually asks of the context. */
    private static ExtensionContext context() {
        return (ExtensionContext) java.lang.reflect.Proxy.newProxyInstance(
                NoSecretInHeapTest.class.getClassLoader(),
                new Class<?>[] {ExtensionContext.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getDisplayName" -> "a test of the extension itself";
                    case "toString" -> "context";
                    case "hashCode" -> 1;
                    case "equals" -> proxy == arguments[0];
                    default -> null;
                });
    }

    /** {@code assertAbsent} in the middle of a program - clean, or after leaking. */
    public static final class AssertAbsentProbe {

        static String password;

        public static void main(String[] arguments) throws Exception {
            if (arguments[1].equals("leak")) {
                password = Files.readString(Path.of(arguments[0])); // seclume-allow: this probe leaks on purpose
            }
            try {
                NoSecretInHeap.assertAbsent(Path.of(arguments[0]));
            } catch (AssertionError found) {
                System.out.println(found.getMessage());
                System.exit(1);
            }
            if (password != null && password.isEmpty()) {
                System.out.println("never");
            }
            System.exit(0);
        }
    }

    /** A process that only knows where the secret is, never what it is. */
    public static final class CleanProbe {

        public static void main(String[] arguments) throws Exception {
            System.setProperty(NoSecretInHeap.SECRET_FILE_PROPERTY, arguments[0]);
            new NoSecretInHeap().afterEach(context());
            System.exit(0);
        }
    }

    /** And one that reads it into a String, as almost every application does. */
    public static final class LeakingProbe {

        static String password;

        public static void main(String[] arguments) throws Exception {
            System.setProperty(NoSecretInHeap.SECRET_FILE_PROPERTY, arguments[0]);
            password = Files.readString(Path.of(arguments[0])); // seclume-allow: this probe leaks on purpose
            try {
                new NoSecretInHeap().afterEach(context());
            } catch (AssertionError found) {
                System.out.println(found.getMessage());
                System.exit(1);
            }
            // Touched once at the end, so the field is live until here.
            if (password.isEmpty()) {
                System.out.println("never");
            }
            System.exit(0);
        }
    }
}
