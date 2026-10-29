package space.seclume.spring;

import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

import space.seclume.heapdump.DumpFolder;

/**
 * The dumps this JVM writes on an {@code OutOfMemoryError}, redacted where they
 * land - and the ones a previous run of it left there.
 *
 * <p>With {@code -XX:+HeapDumpOnOutOfMemoryError} the JVM writes everything it
 * holds, every secret included, to {@code -XX:HeapDumpPath} (its working
 * directory if that is not set). The folder is watched: a dump that is
 * finished and has stopped growing is redacted next to itself by
 * {@link DumpFolder} - every credential of a known shape and its copies
 * overwritten - and the original is deleted. A dump from before a restart,
 * which is where most of them are found, goes the same way once the
 * application is up. Nothing is watched when the JVM writes no dumps.
 *
 * <p>It runs in the application's own JVM, on a daemon thread, after the
 * error - if the JVM survives it - or at the next start. A JVM that exits on
 * the error ({@code -XX:+ExitOnOutOfMemoryError}) leaves the dump to the next
 * start, or to {@code seclume-heapcheck --watch} beside it.
 */
public final class OomDumpRedaction implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(OomDumpRedaction.class.getName());

    /** What the JVM was told about dumps. */
    record VmOptions(boolean dumpOnOutOfMemory, String heapDumpPath) {

        /** This JVM's, or none if it does not say (not HotSpot). */
        static VmOptions current() {
            try {
                com.sun.management.HotSpotDiagnosticMXBean hotSpot = ManagementFactory
                        .getPlatformMXBean(com.sun.management.HotSpotDiagnosticMXBean.class);
                return new VmOptions(
                        Boolean.parseBoolean(hotSpot.getVMOption("HeapDumpOnOutOfMemoryError")
                                .getValue()),
                        hotSpot.getVMOption("HeapDumpPath").getValue());
            } catch (RuntimeException | LinkageError notHotSpot) {
                return new VmOptions(false, "");
            }
        }
    }

    private final Path folder;
    private final DumpFolder.Watch watch;

    private OomDumpRedaction(Path folder, DumpFolder.Watch watch) {
        this.folder = folder;
        this.watch = watch;
    }

    /**
     * The folder to watch: the one configured, else where this JVM writes its
     * dumps - {@code HeapDumpPath} if it is a directory, the directory of the
     * file it names otherwise, the working directory if it is empty - or
     * {@code null} when the JVM writes none.
     */
    static Path folder(String configured, VmOptions vm) {
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured.trim());
        }
        String path = vm.heapDumpPath() == null ? "" : vm.heapDumpPath().trim();
        if (!vm.dumpOnOutOfMemory()) {
            return null;
        }
        if (path.isEmpty()) {
            return Path.of(System.getProperty("user.dir"));
        }
        Path named = Path.of(path);
        return Files.isDirectory(named) ? named : named.toAbsolutePath().getParent();
    }

    /** Starts watching {@code folder} - or nothing, if it is {@code null}. */
    static OomDumpRedaction start(Path folder, Set<String> ignore, Duration interval) {
        if (folder == null) {
            return new OomDumpRedaction(null, null);
        }
        DumpFolder.Settings settings = DumpFolder.Settings.discovery(ignore);
        DumpFolder.Watch watch = DumpFolder.watch(folder, settings, interval, outcome -> {
            if (outcome.ok()) {
                LOG.log(System.Logger.Level.INFO, "seclume: " + outcome.describe());
            } else {
                LOG.log(System.Logger.Level.WARNING, "seclume: " + outcome.describe());
            }
        });
        LOG.log(System.Logger.Level.INFO, "seclume: heap dumps in " + folder
                + " are redacted once they are written");
        return new OomDumpRedaction(folder, watch);
    }

    /** The folder watched, or {@code null}. */
    public Path folder() {
        return folder;
    }

    /** For tests: look now. */
    int checkNow() {
        return watch == null ? 0 : watch.checkNow();
    }

    @Override
    public void close() {
        if (watch != null) {
            watch.close();
        }
    }
}
