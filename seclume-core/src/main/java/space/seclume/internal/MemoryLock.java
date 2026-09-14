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
 * Pins a secret page in RAM: {@code mlock(2)} or {@code VirtualLock}.
 *
 * <p>Without it the kernel may write the page to swap or include it in a core
 * dump - and then the secret is on a disk again, just not in the hprof. Both
 * are operating system services, not guarantees: hitting a capacity limit
 * ({@code RLIMIT_MEMLOCK}, the working set limit on Windows) is the normal
 * case, so a failure here is a warning and not an error.
 */
public final class MemoryLock {

    private static final Logger LOG = System.getLogger(MemoryLock.class.getName());

    /** Can be switched off, for instance in containers with a tight memlock limit. */
    private static final boolean ENABLED =
            Boolean.parseBoolean(System.getProperty("seclume.mlock", "true"));

    private static final MethodHandle LOCK;
    private static final MethodHandle UNLOCK;
    /** Warn only once; otherwise a pool of 20 connections floods the log. */
    private static volatile boolean warned;

    static {
        MethodHandle lock = null;
        MethodHandle unlock = null;
        try {
            Linker linker = Linker.nativeLinker();
            if (Platform.isWindows()) {
                SymbolLookup kernel32 = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
                // BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize);
                FunctionDescriptor descriptor = FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
                lock = linker.downcallHandle(kernel32.find("VirtualLock").orElseThrow(), descriptor);
                unlock = linker.downcallHandle(kernel32.find("VirtualUnlock").orElseThrow(), descriptor);
            } else {
                SymbolLookup libc = linker.defaultLookup();
                // int mlock(const void *addr, size_t len);
                FunctionDescriptor descriptor = FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
                lock = linker.downcallHandle(libc.find("mlock").orElseThrow(), descriptor);
                unlock = linker.downcallHandle(libc.find("munlock").orElseThrow(), descriptor);
            }
        } catch (RuntimeException e) {
            LOG.log(Level.DEBUG, "no memory locking available on this platform", e);
        }
        LOCK = lock;
        UNLOCK = unlock;
    }

    private MemoryLock() {
    }

    /** @return true if the pages are pinned now. */
    public static boolean lock(MemorySegment segment) {
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
        if (UNLOCK == null) {
            return;
        }
        try {
            int ignored = (int) UNLOCK.invokeExact(segment, segment.byteSize());
        } catch (Throwable t) {
            LOG.log(Level.DEBUG, "munlock failed", t);
        }
    }
}
