package space.seclume.internal;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Properties;
import java.util.ServiceLoader;

/**
 * Which {@link Transport} a connection gets, and who decides.
 *
 * <p>This library opens one kind: the {@link SocketTransport} over a
 * {@code SocketChannel}, which is what every driver has always used and what
 * every driver gets unless somebody says otherwise. Anything else arrives as a
 * {@link TransportProvider} on the class path and is asked for by name.
 *
 * <p>The system property {@code seclume.transport} decides, or the URL option
 * of the same name per connection. {@code socket} is the default; a name
 * ending in {@code -if-available} falls back to the socket where the provider
 * says it cannot run here, which is what a test run across platforms needs.
 *
 * <p><b>An unknown name is an error, not a silent fallback.</b> Someone who
 * asks for a transport and quietly gets another one debugs the wrong thing for
 * an afternoon.
 */
public final class Transports {

    private Transports() {
    }

    /** What to use when nobody says otherwise. */
    public static final String DEFAULT = "socket";

    /** The property read when a URL carries no preference. */
    public static final String PROPERTY = "seclume.transport";

    private static final String IF_AVAILABLE = "-if-available";

    /**
     * The transports a URL or the property may name, comma-separated - unset,
     * any provider on the class path. A provider is code the class path
     * already runs, and a URL only picks among them; where URLs come from
     * further away than the class path, this keeps them to the ones meant.
     * {@code socket} is always allowed.
     */
    public static final String ALLOWED = "seclume.transport.allowed";

    private static final System.Logger LOG = System.getLogger(Transports.class.getName());

    /** The names whose provider was named in the log already: once each. */
    private static final java.util.Set<String> SAID = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** The URL option, and the connection property, that name a transport. */
    public static final String OPTION = "transport";

    /**
     * The transport one connection asked for: set around the open by the
     * driver that read the option, and read by {@link #open} when the channel
     * does not name one itself. Per thread, because the option belongs to one
     * connection and the system property to all of them.
     */
    private static final ThreadLocal<String> CHOSEN = new ThreadLocal<>();

    /** Something that opens a connection. */
    @FunctionalInterface
    public interface Opening<T> {
        T open() throws SQLException;
    }

    /**
     * The transport a URL or its properties name: {@code transport=...}, the
     * properties winning as they do for every other option.
     *
     * @return null when neither names one
     */
    public static String option(String url, Properties properties) {
        if (properties != null) {
            String value = properties.getProperty(OPTION);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        if (url == null) {
            return null;
        }
        int query = url.indexOf('?');
        if (query < 0) {
            return null;
        }
        for (String pair : url.substring(query + 1).split("[&;]")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && pair.substring(0, equals).trim().equalsIgnoreCase(OPTION)) {
                String value = pair.substring(equals + 1).trim();
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }

    /**
     * Opens a connection with {@code kind} as its transport - every channel it
     * opens on this thread that names none takes it. Null leaves the choice to
     * the system property.
     */
    public static <T> T using(String kind, Opening<T> opening) throws SQLException {
        if (kind == null) {
            return opening.open();
        }
        String before = CHOSEN.get();
        CHOSEN.set(kind);
        try {
            return opening.open();
        } finally {
            if (before == null) {
                CHOSEN.remove();
            } else {
                CHOSEN.set(before);
            }
        }
    }

    public static Transport open(String kind, String host, int port, int connectTimeoutMillis)
            throws IOException {
        Transport opened = connect(kind, host, port, connectTimeoutMillis);
        // The login is watched with the same bound as the connect: a server
        // that accepts the connection and then says nothing - an Aurora
        // instance in the middle of a failover did exactly that, 26.09.2026 -
        // would otherwise hold the caller for ever. The driver lifts the
        // watch once logged in (loggedIn), and the connection's own network
        // timeout applies from there.
        if (connectTimeoutMillis > 0) {
            try {
                opened.networkTimeout(connectTimeoutMillis);
            } catch (IOException notOffered) {
                // a transport without a timeout of its own: the login is not watched
            }
            // And a bound on the login as a whole: the watch above counts
            // silence only, and a server that sends a byte now and then kept
            // a login - and the pool's thread and permit - for as long as it
            // liked. seclume.loginBudgetFactor times the connect timeout - at
            // least once it, as everywhere the factor is read: a factor of 0
            // closed every login at once.
            long factor = Math.max(1, Integer.getInteger("seclume.loginBudgetFactor", 3));
            long budget = connectTimeoutMillis * factor;
            watch(opened, budget, "the login to " + host + ":" + port + " did not finish within "
                    + "its budget of " + (budget + 999) / 1000 + " s (seclume.loginBudgetFactor "
                    + factor + " x the connect timeout of " + connectTimeoutMillis + " ms)");
        }
        return opened;
    }

    /**
     * A login's budget: whoever takes it out of {@link #LOGINS} first decides
     * - {@link #loggedIn}, and the connection stays; the task, and it closes
     * it. Cancelled only, the task could already be running when the login
     * finished, and closed the connection the driver had just been given.
     */
    private static final class Watch {
        volatile java.util.concurrent.ScheduledFuture<?> task;
    }

    /** Closes {@code transport} after {@code millis} unless {@link #loggedIn} comes first. */
    static void watch(Transport transport, long millis) {
        watch(transport, millis, null);
    }

    /**
     * As {@link #watch(Transport, long)}; when the budget closes the
     * connection, {@code spent} is what the login's thread is told - see
     * {@link #late(java.sql.SQLException)} - instead of the read the close broke.
     */
    static void watch(Transport transport, long millis, String spent) {
        Watch watch = new Watch();
        Thread login = Thread.currentThread();
        if (spent != null) {
            synchronized (SPENT) {
                SPENT.remove(login);
            }
        }
        LOGINS.put(transport, watch);
        watch.task = Budget.SERVICE.schedule(() -> {
            if (LOGINS.remove(transport, watch)) {
                if (spent != null) {
                    synchronized (SPENT) {
                        SPENT.put(login, spent);
                    }
                }
                transport.close();
            }
        }, millis, java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    /** Threads whose login a budget closed, and what to tell them. */
    private static final java.util.Map<Thread, String> SPENT = new java.util.WeakHashMap<>();

    /**
     * What a failed login is reported as: {@code failure} itself, unless the
     * login's budget closed its connection - then a timeout saying so, with
     * the seconds and the factor, {@code failure} as its cause. Called on the
     * thread that opened the connection, around the whole of the login.
     */
    public static java.sql.SQLException late(java.sql.SQLException failure) {
        String spent;
        synchronized (SPENT) {
            spent = SPENT.remove(Thread.currentThread());
        }
        if (spent == null) {
            return failure;
        }
        return new java.sql.SQLTransientConnectionException(spent, "08001", failure);
    }

    /** Takes the budget off {@code transport}; whether it was still on - then nothing closes it. */
    static boolean lift(Transport transport) {
        Watch watch = LOGINS.remove(transport);
        if (watch == null) {
            return false;
        }
        if (watch.task != null) {
            watch.task.cancel(false);
        }
        return true;
    }

    /** Logins under way, and what closes each when its budget is spent. */
    private static final java.util.Map<Transport, Watch> LOGINS =
            new java.util.concurrent.ConcurrentHashMap<>();

    private static final class Budget {
        static final java.util.concurrent.ScheduledExecutorService SERVICE =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "seclume-login-budget");
                    t.setDaemon(true);
                    return t;
                });
    }

    /** Runs {@code task} after {@code millis}, on the thread that watches logins. */
    static java.util.concurrent.ScheduledFuture<?> after(long millis, Runnable task) {
        return Budget.SERVICE.schedule(task, millis, java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    /** The login is done: lifts the watch {@link #open} set on it. */
    public static void loggedIn(Transport transport) {
        lift(transport);
        try {
            transport.networkTimeout(0);
        } catch (IOException notOffered) {
            // nothing was watched
        }
    }

    /**
     * The one provider of {@code name}, or null. The first of two used to
     * win without a word: a second jar offering the same name - an old
     * version, or one put there to carry the connections - decided by class
     * path order which of them saw every byte. Two are an error now, naming
     * both.
     */
    static TransportProvider only(String name, Iterable<TransportProvider> providers)
            throws IOException {
        TransportProvider found = null;
        for (TransportProvider provider : providers) {
            if (!name.equalsIgnoreCase(provider.name())) {
                continue;
            }
            if (found != null) {
                throw new IOException("two transports are called '" + name + "': "
                        + where(found) + " and " + where(provider) + " - remove one");
            }
            found = provider;
        }
        return found;
    }

    /** Refuses a name {@link #ALLOWED} does not list, where it is set. */
    static void allowed(String name) throws IOException {
        String list = System.getProperty(ALLOWED);
        if (list == null || list.isBlank() || DEFAULT.equals(name)) {
            return;
        }
        for (String allowed : list.split(",")) {
            if (allowed.trim().equalsIgnoreCase(name)) {
                return;
            }
        }
        throw new IOException("the transport '" + name + "' is not one " + ALLOWED
                + " allows (" + list.trim() + ") - nothing was opened");
    }

    private static String where(TransportProvider provider) {
        java.security.CodeSource source = provider.getClass().getProtectionDomain()
                .getCodeSource();
        return provider.getClass().getName()
                + (source == null || source.getLocation() == null ? ""
                        : " from " + source.getLocation());
    }

    private static Transport connect(String kind, String host, int port,
                                     int connectTimeoutMillis) throws IOException {
        String chosen = CHOSEN.get();
        String wanted = kind != null && !kind.isBlank() ? kind
                : chosen != null ? chosen
                : System.getProperty(PROPERTY, DEFAULT);
        String name = wanted.toLowerCase(Locale.ROOT);
        boolean orSocket = name.endsWith(IF_AVAILABLE);
        if (orSocket) {
            name = name.substring(0, name.length() - IF_AVAILABLE.length());
        }
        if (DEFAULT.equals(name)) {
            return SocketTransport.connect(host, port, connectTimeoutMillis);
        }
        allowed(name);
        TransportProvider provider = only(name, ServiceLoader.load(TransportProvider.class));
        if (provider != null) {
            if (SAID.add(name)) {
                LOG.log(System.Logger.Level.INFO, "seclume: connections with transport '" + name
                        + "' go through " + where(provider));
            }
            if (orSocket && !provider.available()) {
                return SocketTransport.connect(host, port, connectTimeoutMillis);
            }
            return provider.connect(host, port, connectTimeoutMillis);
        }
        if (orSocket) {
            return SocketTransport.connect(host, port, connectTimeoutMillis);
        }
        throw new IOException("unknown transport '" + wanted + "' - this library offers "
                + DEFAULT + ", and nothing on the class path offers that name");
    }
}
