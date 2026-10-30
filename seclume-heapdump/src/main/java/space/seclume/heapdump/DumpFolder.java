package space.seclume.heapdump;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * The heap dumps a JVM leaves behind - {@code -XX:+HeapDumpOnOutOfMemoryError}
 * into {@code -XX:HeapDumpPath} - and the Flight Recorder recordings
 * ({@code -XX:StartFlightRecording:dumponexit=true,filename=...}), redacted
 * where they lie.
 *
 * <p>A dump written on an {@code OutOfMemoryError} is the one nobody asked
 * for: it lands on a volume, outlives the container, is copied into a ticket,
 * and holds every secret the process had. Here each finished dump in a folder
 * is redacted with {@link Redactor} into a copy next to it -
 * {@code java_pid1.hprof} becomes {@code java_pid1-20261030T001500Z.redacted.hprof},
 * stamped with the dump's time, so that the next dump of a process with the
 * same pid finds its name free - and the original is deleted. A recording
 * becomes {@code <name>-<time>.redacted.jfr} the same way; see {@link Recordings}.
 *
 * <p>Only a <b>finished</b> dump is touched: HotSpot ends one with a
 * {@code HEAP DUMP END} record, and a dump still being written does not end
 * with one yet; a recording is finished when every chunk in it is, the last
 * one ending where the file does. Watching also waits for the size to stay the same between two
 * looks. A dump that cannot be made clean keeps its original - with a failure
 * in the outcome - unless {@link Settings#deleteUnredactable()} says to delete
 * it, which loses the dump but not the secrets.
 */
public final class DumpFolder {

    /** What a redacted copy's name ends with. */
    public static final String REDACTED = ".redacted.hprof";
    /** What a redacted recording's name ends with. */
    public static final String REDACTED_RECORDING = ".redacted.jfr";
    private static final byte[] HEADER = "JAVA PROFILE ".getBytes(StandardCharsets.US_ASCII); // seclume-allow: the format's own name
    private static final int HEAP_DUMP_END = 0x2c;
    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    /** A partial copy older than this was left by a redaction that died. */
    private static final Duration STALE_PART = Duration.ofHours(1);

    private DumpFolder() {
    }

    /**
     * How the dumps are redacted.
     *
     * @param needles            named secrets
     * @param discover           whether to look for credentials of known shapes
     * @param ignore             detectors left out
     * @param deleteUnredactable delete a dump that cannot be made clean, rather than keep it
     * @param offHeap            the application's own secrets, searched without a heap
     *                           copy, or {@code null}
     */
    public record Settings(List<Redactor.Needle> needles, boolean discover, Set<String> ignore,
            boolean deleteUnredactable, OffHeapSecrets offHeap) {

        public Settings {
            needles = List.copyOf(needles);
            ignore = Set.copyOf(ignore);
            if (needles.isEmpty() && offHeap == null && !discover) {
                throw new IllegalArgumentException("nothing to redact: name a secret or discover");
            }
        }

        public Settings(List<Redactor.Needle> needles, boolean discover, Set<String> ignore,
                boolean deleteUnredactable) {
            this(needles, discover, ignore, deleteUnredactable, null);
        }

        /** Discovery alone - what an application can do with its own dumps. */
        public static Settings discovery(Set<String> ignore) {
            return new Settings(List.of(), true, ignore, false);
        }

        /** The same, with the application's own secrets, kept off the heap, looked for too. */
        public Settings with(OffHeapSecrets secrets) {
            return new Settings(needles, discover, ignore, deleteUnredactable, secrets);
        }
    }

    /**
     * One dump: where its redacted copy went, or why there is none.
     *
     * @param redacted the copy, or {@code null}
     * @param report   what was overwritten, or {@code null}
     * @param failure  why the dump is not redacted, or {@code null}
     * @param deleted  whether the original is gone
     */
    public record Outcome(Path original, Path redacted, Redactor.Report report, String failure,
            boolean deleted) {

        public boolean ok() {
            return failure == null;
        }

        /** One line for a log: counts and names, never a value. */
        public String describe() {
            if (ok()) {
                return original + " redacted to " + redacted.getFileName() + " - "
                        + report.regions() + " place(s) overwritten, " + report.stringHashes()
                        + " String hash(es) cleared; the original is deleted";
            }
            return original + " NOT redacted - " + failure + (deleted
                    ? "; the dump is deleted" : "; the dump is kept and still holds its secrets");
        }
    }

    /**
     * Whether {@code file} is an HPROF dump that was written to its end - the
     * header, and the {@code HEAP DUMP END} record HotSpot writes last - or a
     * Flight Recorder recording whose every chunk is finished.
     */
    public static boolean complete(Path file) throws IOException {
        if (recording(file)) {
            return Recordings.complete(file);
        }
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = channel.size();
            if (size < HEADER.length + 9) {
                return false;
            }
            // seclume-allow: the file's header and last record - structure, no secret
            ByteBuffer head = ByteBuffer.allocate(HEADER.length);
            channel.read(head, 0);
            if (!java.util.Arrays.equals(head.array(), HEADER)) {
                return false;
            }
            // seclume-allow: the file's header and last record - structure, no secret
            ByteBuffer tail = ByteBuffer.allocate(9);
            channel.read(tail, size - 9);
            tail.flip();
            if ((tail.get() & 0xff) != HEAP_DUMP_END) {
                return false;
            }
            tail.getInt();                        // the time offset, whatever it is
            return tail.getInt() == 0;            // a record without a body
        }
    }

    /** Whether {@code file} is named as a recording: {@code .jfr}. */
    private static boolean recording(Path file) {
        return file.getFileName().toString().endsWith(".jfr");
    }

    /** The dumps and recordings in {@code folder} that wait for redaction - finished or not. */
    public static List<Path> candidates(Path folder) throws IOException {
        try (Stream<Path> files = Files.list(folder)) {
            return files.filter(Files::isRegularFile)
                    .filter(file -> {
                        String name = file.getFileName().toString();
                        return (name.endsWith(".hprof") || name.endsWith(".jfr"))
                                && !name.endsWith(REDACTED) && !name.endsWith(REDACTED_RECORDING)
                                && !name.startsWith(".");
                    })
                    .sorted()
                    .toList();
        }
    }

    /**
     * Where the redacted copy of {@code dump} goes: its name, the dump's time,
     * {@code .redacted.hprof} - or {@code .redacted.jfr} for a recording.
     */
    static Path target(Path dump) throws IOException {
        String name = dump.getFileName().toString();
        boolean recording = recording(dump);
        String base = name.substring(0, name.length() - (recording ? ".jfr" : ".hprof").length());
        String suffix = recording ? REDACTED_RECORDING : REDACTED;
        String stamp = STAMP.format(Files.getLastModifiedTime(dump).toInstant());
        Path target = dump.resolveSibling(base + "-" + stamp + suffix);
        for (int i = 2; Files.exists(target); i++) {
            target = dump.resolveSibling(base + "-" + stamp + "-" + i + suffix);
        }
        return target;
    }

    /** Redacts one finished dump and deletes it; see the class comment for what happens on failure. */
    public static Outcome redact(Path dump, Settings settings) {
        Path target = null;
        try {
            if (!complete(dump)) {
                return new Outcome(dump, null, null, recording(dump)
                        ? "not a finished Flight Recorder recording" : "not a finished HPROF dump",
                        false);
            }
            target = target(dump);
            Redactor.Report report = Redactor.redact(dump, target, settings.needles(),
                    settings.offHeap(), settings.discover(), settings.ignore());
            Files.delete(dump);
            return new Outcome(dump, target, report, null, true);
        } catch (IOException | RuntimeException e) {
            String failure = e instanceof Redactor.Incomplete ? e.getMessage()
                    : e.getClass().getSimpleName() + ": " + e.getMessage();
            boolean deleted = false;
            if (settings.deleteUnredactable()) {
                try {
                    deleted = Files.deleteIfExists(dump);
                } catch (IOException couldNot) {
                    failure += "; and it could not be deleted: " + couldNot.getMessage();
                }
            }
            return new Outcome(dump, null, null, failure, deleted);
        }
    }

    /** Every finished dump in {@code folder}, redacted once. */
    public static List<Outcome> redactAll(Path folder, Settings settings) throws IOException {
        removeStaleParts(folder);
        List<Outcome> outcomes = new ArrayList<>();
        for (Path dump : candidates(folder)) {
            if (complete(dump)) {
                outcomes.add(redact(dump, settings));
            }
        }
        return outcomes;
    }

    /**
     * Partial copies left by a redaction that died - they hold what was not
     * overwritten yet. Only old ones: a young one may be another redaction's.
     */
    static void removeStaleParts(Path folder) throws IOException {
        Instant before = Instant.now().minus(STALE_PART);
        try (Stream<Path> files = Files.list(folder)) {
            for (Path part : files.filter(file -> {
                String name = file.getFileName().toString();
                return name.startsWith(".seclume-redact-")
                        && (name.endsWith(".hprof.part") || name.endsWith(".jfr.part"));
            }).toList()) {
                if (Files.getLastModifiedTime(part).toInstant().isBefore(before)) {
                    Files.deleteIfExists(part);
                }
            }
        }
    }

    /**
     * Watches {@code folder}: every {@code interval} it looks, the first time
     * one interval from now, and a dump that is finished and has not grown
     * since the last look is redacted. Each
     * outcome goes to {@code listener}. Close it to stop.
     */
    public static Watch watch(Path folder, Settings settings, Duration interval,
            Consumer<Outcome> listener) {
        return new Watch(folder, settings, interval, listener);
    }

    /** A folder being watched, on a daemon thread of its own. */
    public static final class Watch implements AutoCloseable {

        private final Path folder;
        private final Settings settings;
        private final Consumer<Outcome> listener;
        private final Map<Path, Long> sizes = new HashMap<>();
        /** Dumps that could not be redacted, by when they were written: tried again only if rewritten. */
        private final Map<Path, Instant> failed = new HashMap<>();
        private final Thread thread;
        private volatile boolean closed;

        private Watch(Path folder, Settings settings, Duration interval,
                Consumer<Outcome> listener) {
            this.folder = folder;
            this.settings = settings;
            this.listener = listener;
            long millis = Math.max(100, interval.toMillis());
            // A look, then one an interval later: a dump is taken at the
            // second look that finds it finished and the same size.
            this.thread = new Thread(() -> {
                while (!closed) {
                    try {
                        Thread.sleep(millis);
                    } catch (InterruptedException e) {
                        return;
                    }
                    checkNow();
                }
            }, "seclume-dump-folder " + folder);
            thread.setDaemon(true);
            thread.start();
        }

        /**
         * One look: redacts what has been finished since the last one, and
         * returns how many dumps it took on.
         */
        public synchronized int checkNow() {
            int taken = 0;
            try {
                if (!Files.isDirectory(folder)) {
                    return 0;
                }
                removeStaleParts(folder);
                Map<Path, Long> seen = new HashMap<>();
                List<Path> candidates = candidates(folder);
                failed.keySet().retainAll(candidates);
                for (Path dump : candidates) {
                    long size = Files.size(dump);
                    Instant written = Files.getLastModifiedTime(dump).toInstant();
                    if (written.equals(failed.get(dump))) {
                        continue;                 // said once; not again every few seconds
                    }
                    seen.put(dump, size);
                    Long before = sizes.get(dump);
                    if (before != null && before == size && complete(dump)) {
                        Outcome outcome = redact(dump, settings);
                        if (!outcome.ok() && !outcome.deleted()) {
                            failed.put(dump, written);
                        }
                        listener.accept(outcome);
                        seen.remove(dump);
                        taken++;
                    }
                }
                sizes.clear();
                sizes.putAll(seen);
            } catch (IOException | RuntimeException e) {
                listener.accept(new Outcome(folder, null, null, "the folder could not be read: "
                        + e.getMessage(), false));
            }
            return taken;
        }

        @Override
        public void close() {
            closed = true;
            thread.interrupt();
        }
    }
}
