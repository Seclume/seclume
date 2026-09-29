package space.seclume.tck;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;

/**
 * A POSIX shell for the tests that make their keys, certificates and servers
 * with {@code openssl}, {@code keytool} and a few lines of {@code sh}.
 *
 * <p>{@code /bin/sh} where there is one. On Windows, Git for Windows' - which
 * brings {@code openssl}, {@code perl} and the rest of what the scripts use -
 * with MSYS's path conversion switched off: it would turn {@code -subj
 * /CN=localhost} into a Windows path. With no shell at all, the test is
 * skipped rather than failed: it cannot make what it tests with.
 */
public final class Shell {

    private static final String SH = find();

    private Shell() {
    }

    /** Whether a shell was found. */
    public static boolean available() {
        return SH != null;
    }

    /**
     * {@code sh <arguments>} - a script's path, or {@code -c} and a command.
     * Skips the calling test where there is no shell.
     */
    public static ProcessBuilder builder(String... arguments) {
        Assumptions.assumeTrue(available(), "no POSIX shell here (on Windows: Git for Windows)");
        List<String> command = new ArrayList<>();
        command.add(SH);
        command.addAll(List.of(arguments));
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().put("MSYS_NO_PATHCONV", "1");
        builder.environment().put("MSYS2_ARG_CONV_EXCL", "*");
        return builder;
    }

    private static String find() {
        String configured = System.getenv("SECLUME_SH"); // seclume-allow: where the test shell is, not a secret
        if (configured != null && Files.isExecutable(Path.of(configured))) {
            return configured;
        }
        if (!System.getProperty("os.name", "").toLowerCase().startsWith("windows")) {
            return Files.isExecutable(Path.of("/bin/sh")) ? "/bin/sh" : null;
        }
        List<Path> candidates = new ArrayList<>();
        for (String variable : new String[] {"ProgramFiles", "ProgramW6432", "LOCALAPPDATA"}) {
            String base = System.getenv(variable); // seclume-allow: install directories, not a secret
            if (base != null) {
                candidates.add(Path.of(base, "Git", "bin", "sh.exe"));
                candidates.add(Path.of(base, "Programs", "Git", "bin", "sh.exe"));
            }
        }
        String path = System.getenv("PATH"); // seclume-allow: PATH, to find Git for Windows
        if (path != null) {
            for (String entry : path.split(";")) {
                if (entry.isBlank()) {
                    continue;
                }
                Path directory = Path.of(entry.trim());
                if (Files.isRegularFile(directory.resolve("git.exe"))) {
                    // ...\Git\cmd\git.exe - the shell with its PATH is ...\Git\bin\sh.exe
                    Path git = directory.getParent();
                    if (git != null) {
                        candidates.add(git.resolve("bin").resolve("sh.exe"));
                    }
                }
            }
        }
        for (Path candidate : candidates) {
            if (Files.isRegularFile(candidate)) {
                return candidate.toString();
            }
        }
        return null;
    }
}
