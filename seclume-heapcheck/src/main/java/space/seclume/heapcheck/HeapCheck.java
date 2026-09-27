package space.seclume.heapcheck;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest; // seclume-allow: the checksum of a dump - no secret
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat; // seclume-allow: the checksum of a dump, as hex - no secret
import java.util.List;
import java.util.stream.Stream;

import space.seclume.tck.HeapDumpScanner;

/**
 * Proves for <b>any</b> running Java process whether a secret is in its heap.
 *
 * <pre>{@code
 * java -jar seclume-heapcheck.jar --pid 4711 --secret-file /run/secrets/db
 * java -jar seclume-heapcheck.jar --dump app.hprof --secret-dir /run/secrets/app \
 *         --report heapcheck.md --report heapcheck.json
 * }</pre>
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
 * <p>For an audit it checks several secrets at once - {@code --secret-file}
 * again and again, or {@code --secret-dir} for a mounted Kubernetes secret -
 * in a dump it takes itself or one that exists already ({@code --dump}, say
 * the one {@code -XX:+HeapDumpOnOutOfMemoryError} wrote), and writes what it
 * found as a report ({@code --report}: JSON if the name ends in {@code .json},
 * Markdown otherwise) that names secrets only by their files.
 *
 * <p><b>The secret is never a command-line argument.</b> Arguments are visible
 * to every process on the machine - {@code ps} shows them, and on Linux so does
 * {@code /proc}. It comes from a file, and that file is the one the application
 * itself reads.
 */
public final class HeapCheck {

    private HeapCheck() {
    }

    /** What the command line asked for. */
    record Options(String pid, Path dumpFile, List<Path> secretFiles, List<Path> reports,
                   Path keep) {
    }

    public static void main(String[] arguments) {
        String pid = null;
        Path dumpFile = null;
        Path keep = null;
        List<Path> secretFiles = new ArrayList<>();
        List<Path> reports = new ArrayList<>();
        for (int i = 0; i < arguments.length; i++) {
            switch (arguments[i]) {
                case "--pid" -> pid = next(arguments, ++i, "--pid");
                case "--dump" -> dumpFile = Path.of(next(arguments, ++i, "--dump"));
                case "--secret-file" -> secretFiles.add(Path.of(next(arguments, ++i,
                        "--secret-file")));
                case "--secret-dir" -> secretFiles.addAll(directory(Path.of(next(arguments,
                        ++i, "--secret-dir"))));
                case "--report" -> reports.add(Path.of(next(arguments, ++i, "--report")));
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
        if ((pid == null) == (dumpFile == null) || secretFiles.isEmpty()) {
            if (pid != null && dumpFile != null) {
                System.err.println("--pid and --dump both given - one of them, please: a "
                        + "process to dump, or a dump that exists");
            }
            usage();
            System.exit(2);
            return;
        }
        if (dumpFile != null && keep != null) {
            System.err.println("--keep-dump is for a dump this tool takes; --dump is kept "
                    + "anyway");
            System.exit(2);
            return;
        }
        System.exit(run(new Options(pid, dumpFile, secretFiles, reports, keep)));
    }

    /** The one-process, one-secret check, as it always was. */
    static int run(String pid, Path secretFile, Path keep) {
        return run(new Options(pid, null, List.of(secretFile), List.of(), keep));
    }

    static int run(Options options) {
        List<Secret> secrets = new ArrayList<>();
        for (Path file : options.secretFiles()) {
            Secret secret = Secret.read(file);
            if (secret == null) {
                return 2;
            }
            secrets.add(secret);
        }

        boolean takesDump = options.dumpFile() == null;
        Path dump = takesDump ? options.keep() : options.dumpFile();
        try {
            AuditReport.Target target;
            if (takesDump) {
                if (dump == null) {
                    dump = Files.createTempFile("seclume-heapcheck-", ".hprof");
                    Files.delete(dump);           // the JVM insists on writing it itself
                }
                System.out.println("asking process " + options.pid() + " for a heap dump ...");
                ProcessHeap.Jvm jvm = ProcessHeap.dump(options.pid(), dump);
                target = new AuditReport.Target(options.pid(), jvm, null);
            } else {
                if (!Files.isRegularFile(dump)) {
                    System.err.println("no heap dump at " + dump);
                    return 2;
                }
                target = new AuditReport.Target(null, null, dump.toString());
            }
            long size = Files.size(dump);
            System.out.println("dump is " + size / (1024 * 1024) + " MB, searching for "
                    + secrets.size() + " secret(s)");
            List<AuditReport.SecretResult> results = new ArrayList<>();
            for (Secret secret : secrets) {
                results.add(new AuditReport.SecretResult(secret.source().toString(),
                        secret.binary(), secret.scan(dump)));
            }
            AuditReport report = new AuditReport(Instant.now(), host(),
                    target, new AuditReport.Dump(size, sha256(dump), !takesDump
                            || options.keep() != null), results);
            print(report);
            for (Path file : options.reports()) {
                Files.writeString(file, file.getFileName().toString().endsWith(".json")
                        ? report.json() : report.markdown(), StandardCharsets.UTF_8);
                System.out.println("report written to " + file);
            }
            return report.clean() ? 0 : 1;
        } catch (IOException | RuntimeException e) {
            System.err.println("could not check " + (takesDump ? "process " + options.pid()
                    : dump) + " - " + e.getMessage());
            return 2;
        } finally {
            if (takesDump && options.keep() == null && dump != null) {
                deleteQuietly(dump);
            } else if (takesDump && dump != null) {
                System.out.println();
                System.out.println("the dump was kept at " + dump
                        + " - it contains everything the process had in memory, "
                        + "including these secrets. Delete it when you are done.");
            }
        }
    }

    private static void print(AuditReport report) {
        String where = report.target().pid() != null
                ? "the heap of process " + report.target().pid() : "the heap dump";
        for (AuditReport.SecretResult secret : report.secrets()) {
            System.out.println();
            if (!secret.found()) {
                System.out.println("NOT FOUND - the secret from " + secret.source()
                        + " is not in " + where + ".");
                continue;
            }
            System.out.println("FOUND - the secret from " + secret.source() + " is in "
                    + where + ", " + secret.findings().size() + " time(s):");
            for (var finding : secret.findings()) {
                System.out.println("  " + finding);
            }
        }
        System.out.println();
        if (report.clean()) {
            System.out.println("That is a statement about this moment, not a guarantee: "
                    + "a secret can arrive in the heap later, and one that was there "
                    + "may have been overwritten already.");
        } else {
            System.out.println("Every heap dump of this process carries the password - "
                    + "including the one that goes to a vendor's support.");
        }
    }

    /** A secret to look for: text, or - when the file is not UTF-8 - bytes, a key. */
    private record Secret(Path source, String text, byte[] bytes) {

        boolean binary() {
            return bytes != null;
        }

        List<space.seclume.tck.HeapDumpScanner.Finding> scan(Path dump) throws IOException {
            return binary() ? space.seclume.tck.HeapDumpScanner.scanBytes(dump, bytes)
                    : space.seclume.tck.HeapDumpScanner.scan(dump, text);
        }

        /** The secret in {@code file}, or null after saying why not. */
        static Secret read(Path file) {
            byte[] content;
            try {
                // The one place in this repository where a secret goes to the
                // heap on purpose: it is the pattern being searched for, and this
                // process is the searcher, not the one under examination.
                content = Files.readAllBytes(file); // seclume-allow: the searcher needs the pattern it hunts for
            } catch (IOException e) {
                System.err.println("cannot read " + file + " - " + e.getMessage());
                return null;
            }
            String text;
            try {
                text = StandardCharsets.UTF_8.newDecoder() // seclume-allow: the searcher needs the pattern it hunts for
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(content)).toString().strip();
            } catch (CharacterCodingException e) {
                return new Secret(file, null, content);
            }
            if (text.isEmpty()) {
                System.err.println(file + " is empty - without a secret there is nothing "
                        + "to look for, and a check that looks for nothing always passes");
                return null;
            }
            return new Secret(file, text, null);
        }
    }

    /** Every file in a mounted secret - Kubernetes' {@code ..data} links left out. */
    private static List<Path> directory(Path directory) {
        try (Stream<Path> files = Files.list(directory)) {
            List<Path> found = files.filter(file -> !file.getFileName().toString()
                            .startsWith("."))
                    .filter(Files::isRegularFile)
                    .sorted()
                    .toList();
            if (found.isEmpty()) {
                System.err.println("no secret files in " + directory);
                System.exit(2);
            }
            return found;
        } catch (IOException e) {
            System.err.println("cannot list " + directory + " - " + e.getMessage());
            System.exit(2);
            return List.of();
        }
    }

    private static String sha256(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[1 << 16];
            for (int n; (n = in.read(buffer)) > 0; ) {
                digest.update(buffer, 0, n);
            }
            return HexFormat.of().formatHex(digest.digest()); // seclume-allow: a dump's checksum - no secret
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JDK has SHA-256", e);
        }
    }

    private static String host() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "unknown";
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
                usage: java -jar seclume-heapcheck.jar (--pid <pid> | --dump <file.hprof>)
                                                       (--secret-file <path> | --secret-dir <dir>)...
                                                       [--report <file>]... [--keep-dump <path>]

                  --pid          the Java process to examine; its heap is dumped, searched
                                 and the dump deleted again
                  --dump         a heap dump that exists already - from
                                 -XX:+HeapDumpOnOutOfMemoryError, jcmd, a support case
                  --secret-file  a file holding a secret to look for - never the secret
                                 itself as an argument, because arguments are visible to
                                 every process on this machine; may be given again
                  --secret-dir   every file in this directory is a secret - a mounted
                                 Kubernetes secret, say
                  --report       write what was found to this file: JSON if it ends in
                                 .json, Markdown otherwise; may be given again. It names
                                 secrets by their files and holds none of them
                  --keep-dump    with --pid: write the dump here and keep it

                exit code: 0 nothing found, 1 a secret is in the heap, 2 the check
                could not run.""");
    }
}
