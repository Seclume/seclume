package space.seclume.heapcheck;

import space.seclume.heapdump.Attribution;
import space.seclume.heapdump.Discovery;
import space.seclume.heapdump.DumpFolder;
import space.seclume.heapdump.Redactor;

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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * found as a report ({@code --report}: SARIF for {@code .sarif} or {@code .sarif.json},
 * JSON for {@code .json}, Markdown otherwise) that names secrets only by their files.
 *
 * <p><b>The secret is never a command-line argument.</b> Arguments are visible
 * to every process on the machine - {@code ps} shows them, and on Linux so does
 * {@code /proc}. It comes from a file, and that file is the one the application
 * itself reads.
 */
public final class HeapCheck {

    /** For the names of dumps a process writes where others may look. */
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    private HeapCheck() {
    }

    /**
     * What the command line asked for.
     *
     * @param discover whether to look for credentials of known shapes as well
     *                 as - or instead of - the named ones
     * @param ignore   detectors to leave out of the discovery
     * @param attribute whether to work out what holds each raw finding -
     *                 three more passes over the dump, on by default
     * @param redact   where to write a copy of the dump with every secret found
     *                 overwritten, or {@code null}
     * @param dumpDir  where the process writes its dump, as the process sees the
     *                 file system; {@code null} for the temporary directory
     * @param inTarget whether the paths given are in the <b>process's</b> file
     *                 system - this check runs beside it, in a container of its
     *                 own ({@code kubectl debug --target}) - and are reached
     *                 through {@code /proc/<pid>/root}
     */
    record Options(String pid, Path dumpFile, List<Path> secretFiles, List<Path> reports,
                   Path keep, boolean discover, Set<String> ignore, boolean attribute,
                   Path redact, Path dumpDir, boolean inTarget) {

        Options(String pid, Path dumpFile, List<Path> secretFiles, List<Path> reports,
                Path keep, boolean discover, Set<String> ignore, boolean attribute,
                Path redact) {
            this(pid, dumpFile, secretFiles, reports, keep, discover, ignore, attribute, redact,
                    null, false);
        }

        /** Where a path of the process's file system is from here. */
        Path local(Path path) {
            if (!inTarget) {
                return path;
            }
            Path absolute = path.isAbsolute() ? path : Path.of("/").resolve(path);
            return Path.of("/proc", pid, "root").resolve(
                    absolute.getRoot().relativize(absolute).toString());
        }

        Options(String pid, Path dumpFile, List<Path> secretFiles, List<Path> reports,
                Path keep) {
            this(pid, dumpFile, secretFiles, reports, keep, false, Set.of(), true, null);
        }

        Options(String pid, Path dumpFile, List<Path> secretFiles, List<Path> reports,
                Path keep, boolean discover, Set<String> ignore) {
            this(pid, dumpFile, secretFiles, reports, keep, discover, ignore, true, null);
        }

        Options(String pid, Path dumpFile, List<Path> secretFiles, List<Path> reports,
                Path keep, boolean discover, Set<String> ignore, boolean attribute) {
            this(pid, dumpFile, secretFiles, reports, keep, discover, ignore, attribute, null);
        }
    }

    public static void main(String[] arguments) {
        String pid = null;
        Path dumpFile = null;
        Path keep = null;
        List<Path> secretFiles = new ArrayList<>();
        List<Path> reports = new ArrayList<>();
        boolean discover = false;
        boolean attribute = true;
        Path redact = null;
        Path dumpDir = null;
        boolean inTarget = false;
        List<Path> secretDirs = new ArrayList<>();
        Path redactDir = null;
        Path watch = null;
        java.time.Duration interval = java.time.Duration.ofSeconds(10);
        boolean deleteUnredactable = false;
        Set<String> ignore = new LinkedHashSet<>();
        for (int i = 0; i < arguments.length; i++) {
            switch (arguments[i]) {
                case "--discover" -> discover = true;
                case "--no-attribution" -> attribute = false;
                case "--redact" -> redact = Path.of(next(arguments, ++i, "--redact"));
                case "--ignore" -> ignore.add(next(arguments, ++i, "--ignore"));
                case "--list-detectors" -> {
                    System.out.print(Discovery.describe());
                    System.exit(0);
                }
                case "--pid" -> pid = next(arguments, ++i, "--pid");
                case "--dump" -> dumpFile = Path.of(next(arguments, ++i, "--dump"));
                case "--secret-file" -> secretFiles.add(Path.of(next(arguments, ++i,
                        "--secret-file")));
                case "--secret-dir" -> secretDirs.add(Path.of(next(arguments, ++i,
                        "--secret-dir")));
                case "--dump-dir" -> dumpDir = Path.of(next(arguments, ++i, "--dump-dir"));
                case "--in-target" -> inTarget = true;
                case "--redact-dir" -> redactDir = Path.of(next(arguments, ++i, "--redact-dir"));
                case "--watch" -> watch = Path.of(next(arguments, ++i, "--watch"));
                case "--interval" -> interval = seconds(next(arguments, ++i, "--interval"));
                case "--delete-unredactable" -> deleteUnredactable = true;
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
        if (!ignore.isEmpty() && !discover) {
            System.err.println("--ignore leaves a detector out of --discover, which was not "
                    + "asked for");
            System.exit(2);
            return;
        }
        for (String id : ignore) {
            if (!Discovery.ids().contains(id)) {
                System.err.println("--ignore " + id + ": no such detector - known are "
                        + String.join(", ", Discovery.ids()));
                System.exit(2);
                return;
            }
        }
        if (inTarget && (pid == null || keep != null)) {
            System.err.println("--in-target is for a process this check runs beside, given "
                    + "by --pid; its dump stays where the process is and is deleted there, "
                    + "so --keep-dump does not go with it");
            System.exit(2);
            return;
        }
        if (dumpDir != null && (pid == null || !dumpDir.isAbsolute())) {
            System.err.println("--dump-dir is where a process given by --pid writes its dump, "
                    + "an absolute path: the process resolves a relative one against its own "
                    + "working directory");
            System.exit(2);
            return;
        }
        if (redactDir != null || watch != null) {
            if (pid != null || dumpFile != null || redact != null || keep != null
                    || !reports.isEmpty() || inTarget || dumpDir != null
                    || (redactDir != null && watch != null)) {
                System.err.println("--redact-dir and --watch redact the dumps in a folder: "
                        + "one of the two, with --secret-file, --secret-dir, --discover and "
                        + "--ignore - not with a process, a dump or a report");
                System.exit(2);
                return;
            }
            for (Path dir : secretDirs) {
                secretFiles.addAll(directory(dir));
            }
            if (secretFiles.isEmpty() && !discover) {
                System.err.println("nothing to redact: name a secret or --discover");
                System.exit(2);
                return;
            }
            System.exit(folder(redactDir != null ? redactDir : watch, watch != null, interval,
                    secretFiles, discover, Set.copyOf(ignore), deleteUnredactable));
            return;
        }
        if (deleteUnredactable) {
            System.err.println("--delete-unredactable goes with --redact-dir or --watch");
            System.exit(2);
            return;
        }
        Options mapping = new Options(pid, null, List.of(), List.of(), null, false, Set.of(),
                true, null, null, inTarget);
        for (Path dir : secretDirs) {
            for (Path file : directory(mapping.local(dir))) {
                secretFiles.add(dir.resolve(file.getFileName().toString()));
            }
        }
        if ((pid == null) == (dumpFile == null) || (secretFiles.isEmpty() && !discover)) {
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
        if (redact != null && Files.exists(redact)) {
            System.err.println("--redact " + redact + ": the file exists, and a redaction "
                    + "does not overwrite one");
            System.exit(2);
            return;
        }
        System.exit(run(new Options(pid, dumpFile, secretFiles, reports, keep, discover,
                Set.copyOf(ignore), attribute, redact, dumpDir, inTarget)));
    }

    /** {@code 30s}, {@code 5m}, {@code 1h} or plain seconds. */
    static java.time.Duration seconds(String text) {
        String value = text.trim().toLowerCase(java.util.Locale.ROOT);
        long unit = 1;
        if (value.endsWith("s")) {
            value = value.substring(0, value.length() - 1);
        } else if (value.endsWith("m")) {
            unit = 60;
            value = value.substring(0, value.length() - 1);
        } else if (value.endsWith("h")) {
            unit = 3600;
            value = value.substring(0, value.length() - 1);
        }
        try {
            long amount = Long.parseLong(value);
            if (amount <= 0) {
                throw new NumberFormatException("not positive");
            }
            return java.time.Duration.ofSeconds(Math.multiplyExact(amount, unit));
        } catch (NumberFormatException | ArithmeticException e) {
            System.err.println("--interval " + text + ": a duration such as 10s, 5m or 1h");
            System.exit(2);
            return java.time.Duration.ZERO;
        }
    }

    /**
     * The dumps in {@code folder}, redacted where they lie: once, or - with
     * {@code watch} - every dump that is finished there from now on, until the
     * process is stopped. 0 when every dump taken was redacted, 2 otherwise.
     */
    static int folder(Path folder, boolean watch, java.time.Duration interval,
            List<Path> secretFiles, boolean discover, Set<String> ignore,
            boolean deleteUnredactable) {
        if (!Files.isDirectory(folder)) {
            System.err.println("no folder at " + folder);
            return 2;
        }
        List<Redactor.Needle> needles = new ArrayList<>();
        for (Path file : secretFiles) {
            Secret secret = Secret.read(file, file);
            if (secret == null) {
                return 2;
            }
            needles.add(secret.binary() ? Redactor.Needle.bytes(file.toString(), secret.bytes())
                    : Redactor.Needle.text(file.toString(), secret.text()));
        }
        DumpFolder.Settings settings = new DumpFolder.Settings(needles, discover, ignore,
                deleteUnredactable);
        if (watch) {
            System.out.println("watching " + folder + " every " + interval.toSeconds()
                    + "s: a finished heap dump is redacted next to itself and deleted");
            DumpFolder.Watch watching = DumpFolder.watch(folder, settings, interval,
                    outcome -> (outcome.ok() ? System.out : System.err)
                            .println(outcome.describe()));
            Runtime.getRuntime().addShutdownHook(new Thread(watching::close));
            try {
                Thread.currentThread().join();       // until the process is stopped
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return 0;
        }
        try {
            List<DumpFolder.Outcome> outcomes = DumpFolder.redactAll(folder, settings);
            if (outcomes.isEmpty()) {
                System.out.println("no finished heap dump in " + folder);
            }
            boolean failed = false;
            for (DumpFolder.Outcome outcome : outcomes) {
                (outcome.ok() ? System.out : System.err).println(outcome.describe());
                failed |= !outcome.ok();
            }
            return failed ? 2 : 0;
        } catch (IOException e) {
            System.err.println("could not read " + folder + " - " + e.getMessage());
            return 2;
        }
    }

    /** The one-process, one-secret check, as it always was. */
    static int run(String pid, Path secretFile, Path keep) {
        return run(new Options(pid, null, List.of(secretFile), List.of(), keep));
    }

    static int run(Options options) {
        List<Secret> secrets = new ArrayList<>();
        for (Path file : options.secretFiles()) {
            Secret secret = Secret.read(file, options.local(file));
            if (secret == null) {
                return 2;
            }
            secrets.add(secret);
        }

        boolean takesDump = options.dumpFile() == null;
        Path dump = null;
        try {
            AuditReport.Target target;
            if (takesDump) {
                // The name as the process writes it, and the file as it is
                // read here - the same file, unless the process is in another
                // container.
                Path writtenAs;
                if (options.keep() != null) {
                    writtenAs = options.keep();
                } else if (options.dumpDir() != null || options.inTarget()) {
                    Path directory = options.dumpDir() != null ? options.dumpDir()
                            : Path.of("/tmp");
                    byte[] random = new byte[8];
                    RANDOM.nextBytes(random);
                    // seclume-allow: a random file name - no secret
                    writtenAs = directory.resolve("seclume-heapcheck-" + HexFormat.of()
                            .formatHex(random) + ".hprof");
                } else {
                    writtenAs = Files.createTempFile("seclume-heapcheck-", ".hprof");
                }
                dump = options.local(writtenAs);
                Files.deleteIfExists(dump);       // the JVM insists on writing it itself
                System.out.println("asking process " + options.pid() + " for a heap dump ...");
                ProcessHeap.Jvm jvm = ProcessHeap.dump(options.pid(), writtenAs);
                target = new AuditReport.Target(options.pid(), jvm, null);
            } else {
                dump = options.dumpFile();
                if (!Files.isRegularFile(dump)) {
                    System.err.println("no heap dump at " + dump);
                    return 2;
                }
                target = new AuditReport.Target(null, null, dump.toString());
            }
            long size = Files.size(dump);
            System.out.println("dump is " + size / (1024 * 1024) + " MB, searching for "
                    + secrets.size() + " secret(s)"
                    + (options.discover() ? " and for credentials of known shapes" : ""));
            List<AuditReport.SecretResult> results = new ArrayList<>();
            for (Secret secret : secrets) {
                results.add(new AuditReport.SecretResult(secret.source().toString(),
                        secret.binary(), secret.scan(dump)));
            }
            Discovery.Result discovery = options.discover()
                    ? Discovery.scan(dump, options.ignore()) : null;
            Map<Long, String> heldBy = options.attribute()
                    ? attribute(dump, results, discovery) : Map.of();
            AuditReport report = new AuditReport(Instant.now(), host(),
                    target, new AuditReport.Dump(size, sha256(dump), !takesDump
                            || options.keep() != null), results, discovery, heldBy);
            print(report);
            for (Path file : options.reports()) {
                String name = file.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
                Files.writeString(file, name.endsWith(".sarif") || name.endsWith(".sarif.json")
                        ? report.sarif() : name.endsWith(".json") ? report.json() : report.markdown(),
                        StandardCharsets.UTF_8);
                System.out.println("report written to " + file);
            }
            if (options.redact() != null) {
                return redact(dump, options, secrets);
            }
            return report.clean() ? 0 : 1;
        } catch (IOException | RuntimeException e) {
            System.err.println("could not check " + (takesDump ? "process " + options.pid()
                    : options.dumpFile()) + " - " + e.getMessage());
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

    /**
     * Writes the redacted copy and says what went. 0 when it is written and
     * checked - the copy is then safe to hand on as far as anything looked for
     * goes, whatever the original held; 2 when it could not be made clean.
     */
    private static int redact(Path dump, Options options, List<Secret> secrets)
            throws IOException {
        List<Redactor.Needle> needles = new ArrayList<>();
        for (Secret secret : secrets) {
            needles.add(secret.binary()
                    ? Redactor.Needle.bytes(secret.source().toString(), secret.bytes())
                    : Redactor.Needle.text(secret.source().toString(), secret.text()));
        }
        System.out.println();
        System.out.println("writing a redacted copy to " + options.redact() + " ...");
        try {
            Redactor.Report redacted = Redactor.redact(dump, options.redact(), needles,
                    options.discover(), options.ignore());
            System.out.println("REDACTED - " + redacted.regions() + " place(s) overwritten"
                    + (redacted.echoes() > 0 ? " (" + redacted.echoes() + " of them copies or "
                            + "parts of a discovered credential, found where it has no shape)"
                            : "")
                    + ", " + redacted.stringHashes() + " String hash(es) cleared; the copy was "
                    + "searched again and holds none of what was looked for.");
            System.out.println("That covers the secrets named and the shapes discovery "
                    + "knows; a secret of no known shape that was not named is not touched.");
            return 0;
        } catch (Redactor.Incomplete incomplete) {
            System.err.println("NOT REDACTED - " + incomplete.getMessage());
            return 2;
        }
    }

    /**
     * What holds each raw finding. Not worth failing the check over: a dump
     * whose structure cannot be read still answered the question of whether
     * the secret is in it, so a failure here is said and the report goes on
     * without holders.
     */
    private static Map<Long, String> attribute(Path dump,
            List<AuditReport.SecretResult> results, Discovery.Result discovery) {
        List<Long> offsets = new ArrayList<>();
        for (AuditReport.SecretResult result : results) {
            for (var finding : result.findings()) {
                if ("raw file".equals(finding.source())) {
                    offsets.add(finding.position());
                }
            }
        }
        if (discovery != null) {
            for (Discovery.Found found : discovery.found()) {
                for (Discovery.Occurrence at : found.occurrences()) {
                    offsets.add(at.position());
                }
            }
        }
        if (offsets.isEmpty()) {
            return Map.of();
        }
        try {
            System.out.println("working out what holds " + offsets.size() + " finding(s) ...");
            return Attribution.of(dump,
                    offsets.stream().mapToLong(Long::longValue).toArray());
        } catch (IOException | RuntimeException e) {
            System.err.println("could not work out what holds the findings - "
                    + e.getMessage() + "; the report goes on without it");
            return Map.of();
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
                String holder = "raw file".equals(finding.source())
                        ? report.holderAt(finding.position()) : null;
                System.out.println("  " + finding + (holder == null ? "" : " - held by " + holder));
            }
        }
        if (report.discovery() != null) {
            System.out.println();
            if (report.discovery().clean()) {
                System.out.println("DISCOVERED nothing - no credential of a known shape is in "
                        + where + ".");
            }
            for (Discovery.Found found : report.discovery().found()) {
                System.out.println("DISCOVERED - a " + found.detector().name() + " (`"
                        + found.detector().id() + "`, value #" + found.value() + ") is in "
                        + where + ", " + found.count() + " time(s):");
                for (Discovery.Occurrence at : found.occurrences()) {
                    String holder = report.holderAt(at.position());
                    System.out.println("  " + at + (holder == null ? "" : " - held by " + holder));
                }
            }
        }
        System.out.println();
        if (report.clean()) {
            System.out.println("That is a statement about this moment, not a guarantee: "
                    + "a secret can arrive in the heap later, and one that was there "
                    + "may have been overwritten already.");
        } else {
            System.out.println("Every heap dump of this process carries these credentials - "
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

        /**
         * The secret in {@code file}, read at {@code from} - the same file, or
         * that file in another container's file system - or null after saying
         * why not.
         */
        static Secret read(Path file, Path from) {
            byte[] content;
            try {
                // The one place in this repository where a secret goes to the
                // heap on purpose: it is the pattern being searched for, and this
                // process is the searcher, not the one under examination.
                content = Files.readAllBytes(from); // seclume-allow: the searcher needs the pattern it hunts for
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
                                                       [--secret-file <path> | --secret-dir <dir>]...
                                                       [--discover [--ignore <detector>]...]
                                                       [--report <file>]... [--keep-dump <path>]
                                                       [--redact <copy.hprof>]
                                                       [--dump-dir <dir>] [--in-target]
                       java -jar seclume-heapcheck.jar (--redact-dir <dir> | --watch <dir>)
                                                       [--secret-file ... | --secret-dir ...]
                                                       [--discover [--ignore ...]]
                                                       [--interval 10s] [--delete-unredactable]
                       java -jar seclume-heapcheck.jar --list-detectors

                  --pid          the Java process to examine; its heap is dumped, searched
                                 and the dump deleted again
                  --dump         a heap dump that exists already - from
                                 -XX:+HeapDumpOnOutOfMemoryError, jcmd, a support case
                  --secret-file  a file holding a secret to look for - never the secret
                                 itself as an argument, because arguments are visible to
                                 every process on this machine; may be given again
                  --secret-dir   every file in this directory is a secret - a mounted
                                 Kubernetes secret, say
                  --discover     also look for credentials nobody named, by their shape:
                                 private keys, JWTs, cloud and platform tokens, passwords
                                 in URLs. Reports say which kind, how often and where -
                                 never the value. At least one of --secret-file,
                                 --secret-dir and --discover is needed
                  --ignore       leave one detector out of --discover; may be given again
                  --list-detectors  the detectors --discover uses, and their ids
                  --redact       write a copy of the dump here with every secret found -
                                 named, and with --discover the shapes - overwritten and
                                 the copy checked again; exit 0 when it is clean, 2 when
                                 it could not be made so (the copy is then deleted)
                  --no-attribution  do not work out what holds each finding (a field, a
                                 static, an array, unreferenced) - three more passes
                                 over the dump, which a very large one may not want
                  --report       SARIF for .sarif or .sarif.json, JSON for .json,
                                 Markdown otherwise; may be given again. It names
                                 secrets by their files and holds none of them
                  --keep-dump    with --pid: write the dump here and keep it
                  --dump-dir     with --pid: the directory the process writes its dump
                                 to (absolute, as the process sees it); the temporary
                                 directory by default
                  --redact-dir   redact every finished heap dump in this folder next to
                                 itself (name-<time>.redacted.hprof) and delete it:
                                 the dumps -XX:+HeapDumpOnOutOfMemoryError leaves in
                                 -XX:HeapDumpPath. Exit 0 when all were redacted
                  --watch        the same, for every dump finished there from now on,
                                 until stopped - beside the application, a sidecar
                  --interval     how often --watch looks (10s); a dump is taken when it
                                 is finished and has not grown since the last look
                  --delete-unredactable  a dump that cannot be made clean is deleted
                                 rather than kept
                  --in-target    with --pid: this check runs beside the process, in a
                                 container of its own (kubectl debug --target): the
                                 secret files and --dump-dir are in the process's file
                                 system and are read through /proc/<pid>/root; reports
                                 name them as given. The dump is deleted in place

                exit code: 0 nothing found, 1 a secret is in the heap - named or
                discovered -, 2 the check could not run. With --redact: 0 the copy
                is written and clean, 2 it could not be made so.""");
    }
}
