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
 * blocks per process) is an ordinary condition, so by default a failure is a
 * warning, once, and not an error. Where it must be an error,
 * {@code -Dseclume.mlock.required=true} makes it one: a secret segment whose
 * pages cannot be both pinned and kept out of dumps is then refused, before
 * anything is written into it.
 *
 * <p>The page size is the operating system's, not an assumed 4 KiB. On a
 * kernel with 16 or 64 KiB pages (common on aarch64) a 4 KiB-aligned
 * {@code madvise} fails with {@code EINVAL} - the exclusion silently did not
 * happen - and a 4 KiB {@code munlock} unlocks the whole real page, including
 * the part another live secret sits on.
 */
public final class MemoryLock {

    private static final Logger LOG = System.getLogger(MemoryLock.class.getName());

    /** Can be switched off, for instance in containers with a tight memlock limit. */
    private static final boolean ENABLED =
            Boolean.parseBoolean(System.getProperty("seclume.mlock", "true"));

    /**
     * Fail closed: a page that cannot be pinned and excluded from dumps is an
     * error. Off by default, so that the default behaviour stays what it was.
     */
    private static volatile boolean required =
            Boolean.parseBoolean(System.getProperty("seclume.mlock.required", "false"));

    private static final MethodHandle LOCK;
    private static final MethodHandle UNLOCK;
    /** madvise on Linux, WerRegisterExcludedMemoryBlock on Windows - or null. */
    private static final MethodHandle EXCLUDE;
    /** The way back: MADV_DODUMP, WerUnregisterExcludedMemoryBlock. */
    private static final MethodHandle INCLUDE;
    private static final long PAGE;
    private static final int MADV_DONTDUMP = 16;
    private static final int MADV_DODUMP = 17;
    /** Warn only once; otherwise a pool of 20 connections floods the log. */
    private static volatile boolean warned;
    private static volatile boolean warnedDump;

    /** Tests only: behave as if the operating system had refused. */
    static volatile boolean failLockForTests;
    static volatile boolean failExcludeForTests;

    static {
        MethodHandle lock = null;
        MethodHandle unlock = null;
        MethodHandle exclude = null;
        MethodHandle include = null;
        long page = 4096;
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
                // int getpagesize(void);
                page = libc.find("getpagesize").map(symbol -> {
                    try {
                        int size = (int) linker.downcallHandle(symbol,
                                FunctionDescriptor.of(ValueLayout.JAVA_INT)).invokeExact();
                        return size > 0 && Integer.bitCount(size) == 1 ? (long) size : 4096L;
                    } catch (Throwable t) {
                        return 4096L;
                    }
                }).orElse(4096L);
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
        PAGE = page;
    }

    private MemoryLock() {
    }

    /**
     * How many locked secrets use each page, by page address. mlock, munlock
     * and madvise work on whole pages and count nothing: without this,
     * releasing one secret unlocked - and put back into core dumps - a page
     * another live secret still sits on. Found in review, 25.09.2026.
     *
     * <p>Every native call on these pages happens under this monitor too, not
     * only the counting. Counting inside and releasing outside left a window:
     * one thread found a page free and let go of the monitor, a second put a
     * new secret on that page and excluded it, and then the first thread's
     * {@code MADV_DODUMP} and {@code munlock} landed on the second secret.
     */
    private static final java.util.Map<Long, Integer> PAGES = new java.util.HashMap<>();

    /**
     * Counts the segment's pages, excludes them from dumps and pins them.
     *
     * @return true if the pages are pinned now
     * @throws IllegalStateException with {@code -Dseclume.mlock.required=true},
     *         if the pages could not be both pinned and excluded from dumps;
     *         nothing is then left counted, pinned or excluded
     */
    public static boolean lock(MemorySegment segment) {
        if (segment.byteSize() == 0) {
            return false;
        }
        synchronized (PAGES) {
            for (long page = firstPage(segment); page < endPage(segment); page += PAGE) {
                PAGES.merge(page, 1, Integer::sum);
            }
            boolean excluded = excludeFromDumpsLocked(segment);
            boolean pinned = pinLocked(segment);
            if (required && !(excluded && pinned)) {
                releaseLocked(segment);
                throw new IllegalStateException("seclume.mlock.required is set, and the secret's "
                        + "memory could not be "
                        + (!pinned && !excluded ? "locked into RAM or kept out of crash dumps"
                                : !pinned ? "locked into RAM" : "kept out of crash dumps")
                        + (ENABLED ? "" : " (seclume.mlock=false switches both off)"));
            }
            if (!pinned && ENABLED && LOCK != null && !warned) {
                warned = true;
                LOG.log(Level.WARNING,
                        "seclume could not lock the secret page into RAM; "
                        + "the secret may reach swap. Raise the memlock limit, or set "
                        + "-Dseclume.mlock=false to silence this, or "
                        + "-Dseclume.mlock.required=true to refuse instead.");
            }
            if (!excluded && ENABLED && EXCLUDE != null && !warnedDump) {
                warnedDump = true;
                LOG.log(Level.WARNING,
                        "seclume could not keep the secret page out of crash dumps; "
                        + "a core file may contain the secret. "
                        + "-Dseclume.mlock.required=true refuses instead.");
            }
            return pinned;
        }
    }

    /**
     * The counterpart to {@link #lock}, to be called once per {@code lock} of
     * the same segment, whatever {@code lock} returned. Failures here have no
     * consequences beyond a debug message.
     */
    public static void unlock(MemorySegment segment) {
        if (segment.byteSize() == 0) {
            return;
        }
        synchronized (PAGES) {
            releaseLocked(segment);
        }
    }

    /** Gives back one count per page, and the pages that end up free. Holds PAGES. */
    private static void releaseLocked(MemorySegment segment) {
        if (Platform.isWindows() && INCLUDE != null && ENABLED) {
            try {
                int ignored = (int) INCLUDE.invokeExact(segment);   // exact, per block
            } catch (Throwable t) {
                LOG.log(Level.DEBUG, "including the block in dumps again failed", t);
            }
        }
        // Only the pages nobody else still needs: the last secret on a page
        // releases it, runs of such pages in one call each.
        long runStart = -1;
        for (long page = firstPage(segment); page < endPage(segment); page += PAGE) {
            Integer left = PAGES.computeIfPresent(page, (key, count) -> count > 1 ? count - 1
                    : null);
            boolean free = left == null;
            if (free && runStart < 0) {
                runStart = page;
            } else if (!free && runStart >= 0) {
                releasePages(runStart, page - runStart);
                runStart = -1;
            }
        }
        if (runStart >= 0) {
            releasePages(runStart, endPage(segment) - runStart);
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
        if (UNLOCK == null || !ENABLED) {
            return;
        }
        try {
            int ignored = (int) UNLOCK.invokeExact(pages, length);
        } catch (Throwable t) {
            LOG.log(Level.DEBUG, "munlock failed", t);
        }
    }

    private static boolean pinLocked(MemorySegment segment) {
        if (!ENABLED || LOCK == null || failLockForTests) {
            return false;
        }
        try {
            int result = (int) LOCK.invokeExact(segment, segment.byteSize());
            return Platform.isWindows() ? result != 0 : result == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Pages of live secrets, for the test that holds this to its word. */
    static int pagesInUse() {
        synchronized (PAGES) {
            return PAGES.size();
        }
    }

    /** The page size everything here is aligned to. */
    static long pageSize() {
        return PAGE;
    }

    /** Tests only: switch the fail-closed mode without restarting the JVM. */
    static void requireForTests(boolean value) {
        required = value;
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
        synchronized (PAGES) {
            return excludeFromDumpsLocked(segment);
        }
    }

    private static boolean excludeFromDumpsLocked(MemorySegment segment) {
        if (!ENABLED || EXCLUDE == null || segment.byteSize() == 0 || failExcludeForTests) {
            return false;
        }
        try {
            int result;
            if (Platform.isWindows()) {
                result = (int) EXCLUDE.invokeExact(segment, (int) segment.byteSize());
                return result == 0;                      // S_OK
            }
            long start = firstPage(segment);
            long end = endPage(segment);
            result = (int) EXCLUDE.invokeExact(MemorySegment.ofAddress(start), end - start,
                    MADV_DONTDUMP);
            return result == 0;
        } catch (Throwable t) {
            return false;
        }
    }
}
