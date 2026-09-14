package space.seclume.heapcheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import space.seclume.tck.HeapDumpScanner;

/**
 * Proves for <b>any</b> running Java process whether a secret is in its heap.
 *
 * <pre>{@code java -jar seclume-heapcheck.jar --pid 4711 --secret-file /run/secrets/db}</pre>
 *
 * <p>This works on applications that have never heard of this library, and that
 * is the point: the problem it is about - the database password sitting in the
 * heap, and therefore in every heap dump that goes to a vendor's support - is
 * widely known and almost never <b>shown</b>. A number on a slide convinces
 * nobody; the byte offset in your own process does.
 *
 * <p>What it does: attaches to the process, asks it for a heap dump, searches
 * that dump for the secret in every encoding it could be in, prints what it
 * found, and deletes the dump again. The dump is the most dangerous file on the
 * machine while it exists, so it exists for as short a time as possible and in
 * a place only this user can read.
 *
 * <p><b>The secret is never a command-line argument.</b> Arguments are visible
 * to every process on the machine - {@code ps} shows them, and on Linux so does
 * {@code /proc}. It comes from a file, and that file is the one the application
 * itself reads.
 */
public final class HeapCheck {

    private HeapCheck() {
    }

    public static void main(String[] arguments) {
        String pid = null;
        Path secretFile = null;
        Path keep = null;
        for (int i = 0; i < arguments.length; i++) {
            switch (arguments[i]) {
                case "--pid" -> pid = next(arguments, ++i, "--pid");
                case "--secret-file" -> secretFile = Path.of(next(arguments, ++i,
                        "--secret-file"));
                case "--keep-dump" -> keep = Path.of(next(arguments, ++i, "--keep-dump"));
                // Somebody typing this is one keystroke from putting a password
                // where every process on the machine can read it. Saying
                // "unknown option" would be true and useless.
                case "--secret", "--password" -> {
                    System.err.println(arguments[i] + " does not exist, and on purpose: a "
                            + "secret as an argument is visible to every process on this "
                            + "machine. Put it in a file and pass --secret-file <path>.");
                    System.exit(2);
                }
                default -> {
                    System.err.println("unknown option " + arguments[i]);
                    usage();
                    System.exit(2);
                }
            }
        }
        if (pid == null || secretFile == null) {
            usage();
            System.exit(2);
            return;
        }
        System.exit(run(pid, secretFile, keep));
    }

    static int run(String pid, Path secretFile, Path keep) {
        String secret;
        try {
            // The one place in this repository where a secret becomes a String
            // on purpose: it is the pattern being searched for, and this
            // process is the searcher, not the one under examination.
            secret = Files.readString(secretFile, StandardCharsets.UTF_8).strip(); // seclume-allow: the searcher needs the pattern it hunts for
        } catch (IOException e) {
            System.err.println("cannot read " + secretFile + " - " + e.getMessage());
            return 2;
        }
        if (secret.isEmpty()) {
            System.err.println(secretFile + " is empty - without a secret there is nothing "
                    + "to look for, and a check that looks for nothing always passes");
            return 2;
        }

        Path dump = keep;
        try {
            if (dump == null) {
                dump = Files.createTempFile("seclume-heapcheck-", ".hprof");
                Files.delete(dump);               // the JVM insists on writing it itself
            }
            System.out.println("asking process " + pid + " for a heap dump ...");
            ProcessHeap.dump(pid, dump);
            System.out.println("dump is " + Files.size(dump) / (1024 * 1024) + " MB, searching");

            List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
            if (findings.isEmpty()) {
                System.out.println();
                System.out.println("NOT FOUND - the secret from " + secretFile
                        + " is not in the heap of process " + pid + ".");
                System.out.println("That is a statement about this moment, not a guarantee: "
                        + "a secret can arrive in the heap later, and one that was there "
                        + "may have been overwritten already.");
                return 0;
            }
            System.out.println();
            System.out.println("FOUND - the secret is in the heap of process " + pid
                    + ", " + findings.size() + " time(s):");
            for (HeapDumpScanner.Finding finding : findings) {
                System.out.println("  " + finding);
            }
            System.out.println();
            System.out.println("Every heap dump of this process carries the password - "
                    + "including the one that goes to a vendor's support.");
            return 1;
        } catch (IOException | RuntimeException e) {
            System.err.println("could not check process " + pid + " - " + e.getMessage());
            return 2;
        } finally {
            if (keep == null && dump != null) {
                deleteQuietly(dump);
            } else if (dump != null) {
                System.out.println();
                System.out.println("the dump was kept at " + dump
                        + " - it contains everything the process had in memory, "
                        + "including this secret. Delete it when you are done.");
            }
        }
    }

    private static void deleteQuietly(Path dump) {
        try {
            Files.deleteIfExists(dump);
        } catch (IOException e) {
            System.err.println("could not delete " + dump + " - delete it by hand, it "
                    + "contains everything the process had in memory");
        }
    }

    private static String next(String[] arguments, int at, String option) {
        if (at >= arguments.length) {
            System.err.println(option + " needs a value");
            usage();
            System.exit(2);
        }
        return arguments[at];
    }

    private static void usage() {
        System.err.println("""
                usage: java -jar seclume-heapcheck.jar --pid <pid> --secret-file <path>
                                                       [--keep-dump <path>]

                  --pid          the Java process to examine
                  --secret-file  the file holding the secret to look for - never the
                                 secret itself as an argument, because arguments are
                                 visible to every process on this machine
                  --keep-dump    write the dump here and keep it; by default it is
                                 written to a temporary file and deleted again

                exit code: 0 nothing found, 1 the secret is in the heap, 2 the check
                could not run.""");
    }
}
