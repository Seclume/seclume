package space.seclume.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The TLS connections of seclume's own stack open in this process, and who
 * opened each - what a checkpoint image would contain: their traffic keys and
 * cipher states lie in native memory that is not a SecretScope. A connection
 * is counted from its handshake until it is released.
 *
 * <p>A checkpoint counted the pool's connections, open secrets and held keys,
 * not these: a MongoDB pool, HTTP keep-alive, a Redis or Kafka client left
 * their session keys in the image, and with SnapStart in every clone of it.
 */
public final class LiveTls {

    private static final Map<Object, String> OPEN = new ConcurrentHashMap<>();

    private LiveTls() {
    }

    public static void opened(Object connection) {
        OPEN.put(connection, origin());
    }

    public static void released(Object connection) {
        OPEN.remove(connection);
    }

    public static int count() {
        return OPEN.size();
    }

    /** Who opened the connections still open - class names, nothing of the keys. */
    public static List<String> origins() {
        return new ArrayList<>(OPEN.values());
    }

    private static String origin() {
        return StackWalker.getInstance().walk(frames -> frames
                .map(StackWalker.StackFrame::getClassName)
                .filter(name -> !name.startsWith("space.seclume.tls.")
                        && !name.startsWith("space.seclume.internal."))
                .findFirst().orElse("?"));
    }
}
