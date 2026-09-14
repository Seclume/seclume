package space.seclume.tck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Searches a heap dump for a secret - in a process of its own.
 *
 * <p>That last part is the whole point. Searching needs the secret as a
 * pattern, and a pattern is a {@code String}; doing it inside the process whose
 * heap is being examined puts the secret into exactly the place the search is
 * about. {@link NoSecretInHeap} therefore forks this class: the dump is written
 * by the test JVM, the searching happens here, and the test JVM never holds the
 * secret at all - only the path to it.
 *
 * <p>Two arguments: the dump and the file holding the secret. Never the secret
 * itself, because arguments are visible to every process on the machine.
 *
 * <p>Exit code 0 when nothing was found, 1 when the secret is in the dump, 2
 * when the search could not run.
 */
public final class ScanDump {

    private ScanDump() {
    }

    public static void main(String[] arguments) {
        if (arguments.length != 2) {
            System.err.println("usage: ScanDump <dump> <secret-file>");
            System.exit(2);
            return;
        }
        Path dump = Path.of(arguments[0]);
        Path secretFile = Path.of(arguments[1]);
        try {
            // The searcher holds the pattern it hunts for - and this process is
            // not the one under examination.
            String secret = Files.readString(secretFile, StandardCharsets.UTF_8).strip(); // seclume-allow: the searcher needs its pattern
            if (secret.isEmpty()) {
                System.err.println(secretFile + " is empty - a search for nothing always "
                        + "passes, which would be worse than no search");
                System.exit(2);
                return;
            }
            List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
            for (HeapDumpScanner.Finding finding : findings) {
                System.out.println(finding);
            }
            System.exit(findings.isEmpty() ? 0 : 1);
        } catch (IOException e) {
            System.err.println("could not search " + dump + " - " + e.getMessage());
            System.exit(2);
        }
    }
}
