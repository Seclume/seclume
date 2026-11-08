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
    }

    static void closed(Object key) {
        HELD.remove(key);
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
