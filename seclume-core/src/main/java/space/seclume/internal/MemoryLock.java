package space.seclume.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;

/**
 * Pins a secret page in RAM - {@code mlock(2)} or {@code VirtualLock} - and
 * keeps it out of crash dumps: {@code madvise(MADV_DONTDUMP)} on Linux,
 * {@code WerRegisterExcludedMemoryBlock} on Windows.
 *
 * <p>Two different leaks, two different calls. A locked page is not written to
 * swap, but a locked page is still in a core dump - {@code mlock} says nothing
 * about dumps, which is what this class once claimed it did. A core file, a
 * crash report sent to a vendor, a checkpoint image: all of them are the
 * process's memory on a disk, and the secret with it, just not in the hprof.
 * Excluding the page closes that.
 *
 * <p>All of it is operating system service, not guarantee: a capacity limit
 * ({@code RLIMIT_MEMLOCK}, the working set on Windows, Windows' 512 excluded
 * blocks per process) is an ordinary condition, so a failure is a warning,
 * once, and not an error.
 */
public final class MemoryLock {

    private static final Logger LOG = System.getLogger(MemoryLock.class.getName());

    /** Can be switched off, for instance in containers with a tight memlock limit. */
    private static final boolean ENABLED =
            Boolean.parseBoolean(System.getProperty("seclume.mlock", "true"));

    private static final MethodHandle LOCK;
    private static final MethodHandle UNLOCK;
    /** madvise on Linux, WerRegisterExcludedMemoryBlock on Windows - or null. */
    private static final MethodHandle EXCLUDE;
    /** The way back: MADV_DODUMP, WerUnregisterExcludedMemoryBlock. */
    private static final MethodHandle INCLUDE;
    private static final long PAGE = 4096;
    private static final int MADV_DONTDUMP = 16;
    private static final int MADV_DODUMP = 17;
    /** Warn only once; otherwise a pool of 20 connections floods the log. */
    private static volatile boolean warned;

    static {
        MethodHandle lock = null;
        MethodHandle unlock = null;
        MethodHandle exclude = null;
        MethodHandle include = null;
        try {
            Linker linker = Linker.nativeLinker();
            if (Platform.isWindows()) {
                SymbolLookup kernel32 = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
                // BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize);
                FunctionDescriptor descriptor = FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
                lock = linker.downcallHandle(kernel32.find("VirtualLock").orElseThrow(), descriptor);
                unlock = linker.downcallHandle(kernel32.find("VirtualUnlock").orElseThrow(), descriptor);
                // HRESULT WerRegisterExcludedMemoryBlock(const void *address, DWORD size);
                // HRESULT WerUnregisterExcludedMemoryBlock(const void *address);
                exclude = kernel32.find("WerRegisterExcludedMemoryBlock").map(symbol -> linker
                        .downcallHandle(symbol, FunctionDescriptor.of(ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS, ValueLayout.JAVA_INT))).orElse(null);
                include = kernel32.find("WerUnregisterExcludedMemoryBlock").map(symbol -> linker
                        .downcallHandle(symbol, FunctionDescriptor.of(ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS))).orElse(null);
            } else {
                SymbolLookup libc = linker.defaultLookup();
                // int mlock(const void *addr, size_t len);
                FunctionDescriptor descriptor = FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
                lock = linker.downcallHandle(libc.find("mlock").orElseThrow(), descriptor);
                unlock = linker.downcallHandle(libc.find("munlock").orElseThrow(), descriptor);
                if (Platform.isLinux()) {
                    // int madvise(void *addr, size_t length, int advice);
                    MethodHandle madvise = libc.find("madvise").map(symbol -> linker
                            .downcallHandle(symbol, FunctionDescriptor.of(ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                                    ValueLayout.JAVA_INT))).orElse(null);
                    exclude = madvise;
                    include = madvise;
                }
            }
        } catch (RuntimeException e) {
            LOG.log(Level.DEBUG, "no memory locking available on this platform", e);
        }
        LOCK = lock;
        UNLOCK = unlock;
        EXCLUDE = exclude;
        INCLUDE = include;
    }

    private MemoryLock() {
    }

    /**
     * How many locked secrets use each page, by page address. mlock, munlock
     * and madvise work on whole pages and count nothing: without this,
     * releasing one secret unlocked - and put back into core dumps - a page
     * another live secret still sits on. Found in review, 25.09.2026.
     */
    private static final java.util.Map<Long, Integer> PAGES = new java.util.HashMap<>();

    /** @return true if the pages are pinned now. */
    public static boolean lock(MemorySegment segment) {
        if (segment.byteSize() > 0) {
            synchronized (PAGES) {
                for (long page = firstPage(segment); page < endPage(segment); page += PAGE) {
                    PAGES.merge(page, 1, Integer::sum);
                }
            }
        }
        excludeFromDumps(segment);
        if (!ENABLED || LOCK == null) {
            return false;
        }
        try {
            int result = (int) LOCK.invokeExact(segment, segment.byteSize());
            boolean ok = Platform.isWindows() ? result != 0 : result == 0;
            if (!ok && !warned) {
                warned = true;
                LOG.log(Level.WARNING,
                        "seclume could not lock the secret page into RAM; "
                        + "the secret may reach swap or a core dump. "
                        + "Raise the memlock limit or set -Dseclume.mlock=false to silence this.");
            }
            return ok;
        } catch (Throwable t) {
            return false;
        }
    }

    /** The counterpart to {@link #lock}; failures here have no consequences. */
    public static void unlock(MemorySegment segment) {
        if (segment.byteSize() == 0) {
            return;
        }
        if (Platform.isWindows() && INCLUDE != null && ENABLED) {
            try {
                int ignored = (int) INCLUDE.invokeExact(segment);   // exact, per block
            } catch (Throwable t) {
                LOG.log(Level.DEBUG, "including the block in dumps again failed", t);
            }
        }
        // Only the pages nobody else still needs: the last secret on a page
        // releases it, runs of such pages in one call each.
        java.util.List<long[]> runs = new java.util.ArrayList<>();
        synchronized (PAGES) {
            long runStart = -1;
            for (long page = firstPage(segment); page < endPage(segment); page += PAGE) {
                Integer left = PAGES.computeIfPresent(page, (key, count) -> count > 1 ? count - 1
                        : null);
                boolean free = left == null;
                if (free && runStart < 0) {
                    runStart = page;
                } else if (!free && runStart >= 0) {
                    runs.add(new long[] {runStart, page});
                    runStart = -1;
                }
            }
            if (runStart >= 0) {
                runs.add(new long[] {runStart, endPage(segment)});
            }
        }
        for (long[] run : runs) {
            releasePages(run[0], run[1] - run[0]);
        }
    }

    private static long firstPage(MemorySegment segment) {
        return segment.address() & -PAGE;
    }

    private static long endPage(MemorySegment segment) {
        return (segment.address() + segment.byteSize() + PAGE - 1) & -PAGE;
    }

    /** munlock (or VirtualUnlock) and, on Linux, back into dumps - for pages no secret uses. */
    private static void releasePages(long start, long length) {
        MemorySegment pages = MemorySegment.ofAddress(start).reinterpret(length);
        if (!Platform.isWindows() && ENABLED && INCLUDE != null) {
            try {
                int ignored = (int) INCLUDE.invokeExact(MemorySegment.ofAddress(start), length,
                        MADV_DODUMP);
            } catch (Throwable t) {
                LOG.log(Level.DEBUG, "including the pages in dumps again failed", t);
            }
        }
        if (UNLOCK == null) {
            return;
        }
        try {
            int ignored = (int) UNLOCK.invokeExact(pages, length);
        } catch (Throwable t) {
            LOG.log(Level.DEBUG, "munlock failed", t);
        }
    }

    /** Pages of live secrets, for the test that holds this to its word. */
    static int pagesInUse() {
        synchronized (PAGES) {
            return PAGES.size();
        }
    }

    /** Whether the platform offers keeping pages out of dumps at all. */
    public static boolean canExcludeFromDumps() {
        return EXCLUDE != null;
    }

    /**
     * Keeps the pages under {@code segment} out of crash dumps. Linux works on
     * whole pages, so the range is widened to them: what else lies on those
     * pages is left out of a dump too, which costs a little debugging and no
     * secret.
     *
     * @return whether it took
     */
    public static boolean excludeFromDumps(MemorySegment segment) {
        if (!ENABLED || EXCLUDE == null || segment.byteSize() == 0) {
            return false;
        }
        try {
            int result;
            if (Platform.isWindows()) {
                result = (int) EXCLUDE.invokeExact(segment, (int) segment.byteSize());
                return result == 0;                      // S_OK
            }
            long start = segment.address() & -PAGE;
            long end = (segment.address() + segment.byteSize() + PAGE - 1) & -PAGE;
            result = (int) EXCLUDE.invokeExact(MemorySegment.ofAddress(start), end - start,
                    MADV_DONTDUMP);
            return result == 0;
        } catch (Throwable t) {
            return false;
        }
    }
}
