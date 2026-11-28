package space.seclume.internal;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * {@code -Dseclume.dumpable=false}: the process made not dumpable,
 * {@code prctl(PR_SET_DUMPABLE, 0)}, before the first secret. Another process
 * of the same user can then neither attach with {@code ptrace} nor read
 * {@code /proc/<pid>/mem}, and the process leaves no core dump.
 *
 * <p>Opt-in, as it takes more than an attacker's way in: {@code jcmd},
 * {@code jstack} and {@code seclume-heapcheck --pid} cannot attach to the
 * process either. Asked for and not to be had - not Linux, or prctl refused -
 * the first secret is refused rather than made in a process that is not what
 * was asked for.
 */
public final class ProcessHardening {

    private static final Logger LOG = System.getLogger(ProcessHardening.class.getName());
    private static final int PR_SET_DUMPABLE = 4;
    private static final int PR_GET_DUMPABLE = 3;

    /** Whether {@code -Dseclume.dumpable=false} asks for it. */
    static final boolean ASKED = "false".equalsIgnoreCase(System.getProperty("seclume.dumpable"));

    private static volatile String refused;
    private static volatile boolean applied;

    private ProcessHardening() {
    }

    /** Applies what was asked for, once; throws if it was asked for and cannot be had. */
    public static void apply() {
        if (!ASKED) {
            return;
        }
        if (!applied) {
            synchronized (ProcessHardening.class) {
                if (!applied) {
                    refused = notDumpable();
                    applied = true;
                    if (refused == null) {
                        LOG.log(Level.INFO, "seclume: the process is not dumpable "
                                + "(-Dseclume.dumpable=false): ptrace and /proc/<pid>/mem are "
                                + "refused to other processes of this user, and so are jcmd and "
                                + "seclume-heapcheck --pid");
                    }
                }
            }
        }
        if (refused != null) {
            throw new IllegalStateException("-Dseclume.dumpable=false asks for a process that is "
                    + "not dumpable, and " + refused + " - no secret is made");
        }
    }

    /** Whether the process is not dumpable now - for tests and diagnostics. */
    public static boolean notDumpableNow() {
        try {
            return Platform.isLinux() && (int) prctl().invokeExact(PR_GET_DUMPABLE, 0L) == 0; // mutation-equivalent: a test JVM is dumpable; the other answer is the child JVM's, in SecretMemoryTest
        } catch (Throwable t) {
            return false;
        }
    }

    /** prctl(PR_SET_DUMPABLE, 0): null when done, else why not. */
    private static String notDumpable() {
        if (!Platform.isLinux()) {
            return "that is Linux's, and this is " + System.getProperty("os.name");
        }
        try {
            int result = (int) prctl().invokeExact(PR_SET_DUMPABLE, 0L);
            return result == 0 ? null : "prctl(PR_SET_DUMPABLE) failed";
        } catch (Throwable t) {
            return "prctl could not be called: " + t.getMessage();
        }
    }

    private static MethodHandle prctl() {
        Linker linker = Linker.nativeLinker();
        // int prctl(int option, unsigned long arg2, ...);
        return linker.downcallHandle(linker.defaultLookup().find("prctl").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG), Linker.Option.firstVariadicArg(1));
    }
}
