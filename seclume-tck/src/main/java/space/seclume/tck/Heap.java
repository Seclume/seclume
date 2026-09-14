package space.seclume.tck;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;

import com.sun.management.HotSpotDiagnosticMXBean;

/**
 * Writing a heap dump - the one operation every probe needs.
 *
 * <p>Always with {@code live=false}: then whatever is merely waiting to be
 * collected is in the file as well. That is the least forgiving setting and the
 * only honest one - an attacker gets exactly this file, and whether an object
 * in it was still reachable is of no interest to them.
 */
public final class Heap {

    private Heap() {
    }

    public static void dump(Path target) throws IOException {
        Files.deleteIfExists(target);
        ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class)
                .dumpHeap(target.toString(), false);
    }

    /** Collect twice, so that nothing lingers merely because of timing. */
    public static void collect() {
        System.gc();
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        System.gc();
    }
}
