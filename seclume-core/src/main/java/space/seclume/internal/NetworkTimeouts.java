package space.seclume.internal;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The watch behind {@code Connection.setNetworkTimeout}: one thread for every
 * connection that has a network timeout, and none for those that do not.
 *
 * <p>The obvious way - a timer armed before each read and cancelled after it -
 * puts a scheduled task on the hot path of every round trip. This turns it
 * round: a transport with a timeout notes when it started to wait
 * ({@link Watched#busySince()}, one {@code nanoTime} per call) and this thread
 * looks at all of them a few times a second. Whatever has been waiting longer
 * than its timeout is closed; the blocked read or write then fails, and the
 * transport reports it as the timeout it was.
 *
 * <p>The price is precision: a timeout fires up to {@link #TICK_MILLIS} late.
 * Network timeouts are set in seconds - HikariCP's are fifteen or thirty - so
 * that is noise, and it keeps the reads themselves free of any scheduling.
 */
public final class NetworkTimeouts {

    /** How often the waiting transports are looked at. */
    static final long TICK_MILLIS = 50;

    /** A transport that can be watched. */
    public interface Watched {
        /** When the current read or write began, from {@code nanoTime}; 0 when idle. */
        long busySince();

        /** The timeout in milliseconds; 0 for none. */
        int timeoutMillis();

        /** Closes it because it waited too long. */
        void expire();
    }

    private static final Set<Watched> WATCHED = ConcurrentHashMap.newKeySet();

    /** Started with the first transport that asks for a timeout. */
    private static final class Clock {
        private static final ScheduledExecutorService SERVICE =
                Executors.newSingleThreadScheduledExecutor(runnable -> {
                    Thread thread = new Thread(runnable, "seclume-network-timeouts");
                    // A watch must never be the reason a JVM does not exit.
                    thread.setDaemon(true);
                    return thread;
                });

        static {
            SERVICE.scheduleWithFixedDelay(NetworkTimeouts::tick, TICK_MILLIS, TICK_MILLIS,
                    TimeUnit.MILLISECONDS);
        }

        static void start() {
            // Loading the class is the start.
        }
    }

    private NetworkTimeouts() {
    }

    /** Watches this transport from now on - or no longer, for a timeout of 0. */
    public static void watch(Watched transport, int timeoutMillis) {
        if (timeoutMillis > 0) {
            WATCHED.add(transport);
            Clock.start();
        } else {
            WATCHED.remove(transport);
        }
    }

    /** Forgets it: closed, it has nothing left to wait for. */
    public static void forget(Watched transport) {
        WATCHED.remove(transport);
    }

    static void tick() {
        long now = System.nanoTime();
        for (Watched transport : WATCHED) {
            long since = transport.busySince();
            int timeout = transport.timeoutMillis();
            if (since != 0 && timeout > 0
                    && now - since > TimeUnit.MILLISECONDS.toNanos(timeout)) {
                WATCHED.remove(transport);
                try {
                    transport.expire();
                } catch (RuntimeException ignored) {
                    // The watch goes on for the others whatever one of them does.
                }
            }
        }
    }
}
