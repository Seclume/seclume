package space.seclume.tck;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Starts a second JVM with the same classpath and waits for it.
 *
 * <p>It gets {@code --enable-native-access=ALL-UNNAMED} because the library
 * uses FFM, and nothing else: no system properties carrying secrets, no
 * arguments carrying secrets.
 */
public final class ChildJvm {

    /** The result of a run - output for debugging, exit code for the test. */
    public record Result(int exitCode, String output) {
    }

    private ChildJvm() {
    }

    public static Result run(Class<?> mainClass, List<String> arguments, long timeoutSeconds)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("--enable-native-access=ALL-UNNAMED");
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(mainClass.getName());
        command.addAll(arguments);

        Path log = Files.createTempFile("seclume-probe-", ".log");
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .redirectOutput(log.toFile())
                    .start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IllegalStateException("the probe did not finish within "
                        + timeoutSeconds + " seconds");
            }
            // seclume-allow: the log of the probe, not a secret - the probe's output is what the caller wants to read
            return new Result(process.exitValue(), Files.readString(log));
        } finally {
            Files.deleteIfExists(log);
        }
    }
}
