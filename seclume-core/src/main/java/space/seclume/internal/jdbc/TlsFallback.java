package space.seclume.internal.jdbc;

import java.lang.System.Logger.Level;
import java.sql.SQLException;
import java.util.concurrent.ConcurrentHashMap;

import space.seclume.tls.TlsVersionRefused;

/**
 * What {@link TlsStack#AUTO} does: this project's stack first, the JDK's for
 * a server that cannot speak it.
 *
 * <p>The change of stack is a new connection, not a second handshake on the
 * old one - the first ClientHello has been answered, and every protocol puts
 * something in front of TLS (an SSLRequest, a MySQL greeting, a TNS connect)
 * that has to be said again. So the four drivers wrap their one-server
 * connect in {@link #connect}, and it runs that connect a second time.
 *
 * <p>Only a {@link TlsVersionRefused} leads there: a server that refused the
 * version before its ServerHello was accepted. A certificate that does not
 * verify, a wrong host name, a refused login - all of those fail as they
 * always did, because the other stack would fail them the same way.
 *
 * <p>A server that needed JSSE is remembered for {@link #RECHECK_MILLIS},
 * so a pool does not try the own stack on every new connection to it, and
 * the warning is logged once per server and period. After that the own stack
 * is tried again: a server upgraded to TLS 1.3 gets it without a restart.
 *
 * <p>Whoever wants no fallback at all - not even one an attacker on the path
 * could provoke by answering the ClientHello with an alert - sets
 * {@code tlsStack=seclume}. What such an attacker gains is JSSE's TLS 1.2
 * with the certificate still checked: the password on this process's heap,
 * not on the wire.
 */
public final class TlsFallback {

    private static final System.Logger LOG = System.getLogger(TlsFallback.class.getName());

    /** How long a server stays on JSSE before the own stack is tried again. */
    static final long RECHECK_MILLIS = 60 * 60 * 1000L;

    /** More servers than this are not remembered; the oldest entries are dropped. */
    private static final int REMEMBERED = 1024;

    /** host:port -> when it last refused the own stack. */
    private static final ConcurrentHashMap<String, Long> NEEDS_JSSE = new ConcurrentHashMap<>();

    private TlsFallback() {
    }

    /** One connect to one server, on the stack it is given. */
    @FunctionalInterface
    public interface Attempt<T> {
        T on(TlsStack stack) throws SQLException;
    }

    /**
     * Runs {@code attempt} on the configured stack, and for {@link TlsStack#AUTO}
     * once more on JSSE if the server refused the own stack's TLS.
     *
     * @param clientCertificate whether a client certificate is configured: its
     *        key is only reachable from the own stack, so there is nothing to
     *        fall back to
     */
    public static <T> T connect(TlsStack configured, boolean clientCertificate, String host,
            int port, Attempt<T> attempt) throws SQLException {
        if (configured != TlsStack.AUTO) {
            return attempt.on(configured);
        }
        if (clientCertificate) {
            return attempt.on(TlsStack.SECLUME);
        }
        String server = host + ":" + port;
        if (remembered(server)) {
            return attempt.on(TlsStack.JSSE);
        }
        try {
            return attempt.on(TlsStack.SECLUME);
        } catch (SQLException failed) {
            TlsVersionRefused refused = versionRefused(failed);
            if (refused == null) {
                throw failed;
            }
            remember(server, refused);
            try {
                return attempt.on(TlsStack.JSSE);
            } catch (SQLException again) {
                again.addSuppressed(failed);
                throw again;
            }
        }
    }

    /** Whether the own stack is skipped for this server for now. */
    static boolean remembered(String server) {
        Long since = NEEDS_JSSE.get(server);
        if (since == null) {
            return false;
        }
        if (System.currentTimeMillis() - since < RECHECK_MILLIS) {
            return true;
        }
        NEEDS_JSSE.remove(server, since);
        return false;
    }

    private static void remember(String server, TlsVersionRefused refused) {
        if (NEEDS_JSSE.size() >= REMEMBERED) {
            NEEDS_JSSE.entrySet().stream()
                    .min(java.util.Map.Entry.comparingByValue())
                    .ifPresent(oldest -> NEEDS_JSSE.remove(oldest.getKey(), oldest.getValue()));
        }
        NEEDS_JSSE.put(server, System.currentTimeMillis());
        LOG.log(Level.WARNING, () -> server + " does not speak seclume's TLS ("
                + refused.getCause().getMessage() + "); connecting with the JDK's TLS "
                + "instead, which copies the password through the heap. Upgrade the server "
                + "to TLS 1.3 (SQL Server: tdsVersion=8.0), or set tlsStack=jsse to say this "
                + "is intended, or tlsStack=seclume to refuse such servers. Trying seclume's "
                + "TLS again in " + RECHECK_MILLIS / 60_000 + " minutes.");
    }

    /** The refusal somewhere in the cause chain, or null. */
    static TlsVersionRefused versionRefused(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof TlsVersionRefused refused) {
                return refused;
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return null;
    }

    /** For tests: forget every server. */
    static void forget() {
        NEEDS_JSSE.clear();
    }
}
