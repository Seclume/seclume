package space.seclume.crypto;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The private keys OpenSSL or CNG holds for this process right now, and who
 * made each - what a checkpoint image would contain. A key is counted from
 * its decoding until it is closed; one that is never closed stays counted,
 * as its key material stays in the backend's memory.
 */
final class LiveKeys {

    private static final Map<Object, String> HELD = new ConcurrentHashMap<>();

    private LiveKeys() {
    }

    static void opened(Object key) {
        HELD.put(key, origin());
        OPENED.put(key, Thread.currentThread().getName() + " at " + where());
    }

    static void closed(Object key) {
        HELD.remove(key);
        OPENED.remove(key);
    }

    /**
     * For a test that finds a key still held and has to say where it was
     * made: the thread and the first calls outside this package. Class and
     * method names only - nothing of the key - and never shown to a user,
     * whose messages carry {@link #origins()}.
     */
    static List<String> details() {
        return new ArrayList<>(OPENED.values());
    }

    private static final Map<Object, String> OPENED = new ConcurrentHashMap<>();

    private static String where() {
        return StackWalker.getInstance().walk(frames -> frames
                .filter(f -> !f.getClassName().startsWith("space.seclume.crypto."))
                .limit(8)
                .map(f -> f.getClassName().substring(f.getClassName().lastIndexOf('.') + 1)
                        + "." + f.getMethodName())
                .collect(java.util.stream.Collectors.joining(" < ")));
    }

    static int count() {
        return HELD.size();
    }

    /** Who made the keys held - the first class outside this package on the stack. */
    static List<String> origins() {
        return new ArrayList<>(HELD.values());
    }

    private static String origin() {
        return StackWalker.getInstance().walk(frames -> frames
                .map(StackWalker.StackFrame::getClassName)
                .filter(name -> !name.startsWith("space.seclume.crypto."))
                .findFirst().orElse("?"));
    }
}
