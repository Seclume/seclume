package space.seclume.spring;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.boot.actuate.management.HeapDumpWebEndpoint;

import space.seclume.heapdump.Discovery;
import space.seclume.heapdump.Redactor;

/**
 * {@code /actuator/heapdump} that serves a redacted copy, never the dump
 * itself.
 *
 * <p>Spring Boot's endpoint hands out the whole heap: every credential the
 * application holds, to whoever may call the endpoint, as a file that then
 * lives on in a ticket or a laptop. This one takes the dump the same way,
 * redacts it with {@link Redactor} - every credential of a known shape and
 * its copies and parts elsewhere overwritten, the {@code String} hashes of
 * what went cleared, the copy searched again - and serves the copy. The
 * dump itself is deleted before the response starts.
 *
 * <p>It fails closed: if the copy cannot be made clean - the check still
 * finds something, the dump's structure cannot be read (OpenJ9 writes no
 * HPROF) - the response is 500 and nothing is served. Only shapes are looked
 * for; the secrets themselves are not known here, and would not be put on
 * this heap to look for them. A credential of no known shape is not touched.
 */
public class SeclumeHeapDumpWebEndpoint extends HeapDumpWebEndpoint {

    private static final System.Logger LOG =
            System.getLogger(SeclumeHeapDumpWebEndpoint.class.getName());

    private final Set<String> ignore;
    private final Source source;

    /** Where the dump comes from, if not from the JVM: a test's file. */
    @FunctionalInterface
    interface Source {
        File dumpHeap(Boolean live) throws IOException, InterruptedException;
    }

    /**
     * @param ignore detectors to leave out, as {@code seclume-heapcheck
     *               --ignore} takes them
     */
    public SeclumeHeapDumpWebEndpoint(Set<String> ignore) {
        this(ignore, null);
    }

    /** With the dump taken by {@code source} rather than by the JVM - for tests. */
    SeclumeHeapDumpWebEndpoint(Set<String> ignore, Source source) {
        for (String id : ignore) {
            if (!Discovery.ids().contains(id)) {
                throw new IllegalArgumentException("seclume.heapdump.ignore: no detector '" + id
                        + "' - known are " + String.join(", ", Discovery.ids()));
            }
        }
        this.ignore = Set.copyOf(ignore);
        this.source = source;
    }

    @Override
    protected HeapDumper createHeapDumper() throws HeapDumperUnavailableException {
        if (source != null) {
            return live -> redacted(source.dumpHeap(live).toPath());
        }
        HeapDumper dumper = super.createHeapDumper();
        return live -> redacted(dumper.dumpHeap(live).toPath());
    }

    /** The redacted copy of {@code dump}, which is deleted whatever happens. */
    File redacted(Path dump) throws IOException {
        Path out = null;
        try {
            Path directory = dump.toAbsolutePath().getParent();
            out = Files.createTempFile(directory, "heap-redacted-", ".hprof");
            Files.delete(out);                    // Redactor makes it, owner-only
            Redactor.Report report = Redactor.redact(dump, out, List.of(), true, ignore);
            LOG.log(System.Logger.Level.INFO, () -> "seclume: heap dump redacted - "
                    + report.regions() + " place(s) overwritten"
                    + (report.discovered() == null || report.discovered().clean() ? ""
                            : " (" + new TreeSet<>(report.discovered().valuesByDetector()
                                    .keySet()) + ")")
                    + ", " + report.stringHashes() + " String hash(es) cleared");
            File served = out.toFile();
            out = null;
            return served;
        } catch (Redactor.Incomplete incomplete) {
            LOG.log(System.Logger.Level.WARNING, "seclume: heap dump not served - "
                    + incomplete.getMessage());
            throw incomplete;
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "seclume: heap dump not served - " + e);
            throw new IOException("the heap dump could not be redacted", e);
        } catch (IOException e) {
            LOG.log(System.Logger.Level.WARNING, "seclume: heap dump not served - " + e);
            throw e;
        } finally {
            Files.deleteIfExists(dump);
            if (out != null) {
                Files.deleteIfExists(out);
            }
        }
    }
}
