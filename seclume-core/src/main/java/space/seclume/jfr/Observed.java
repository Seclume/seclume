package space.seclume.jfr;

import space.seclume.QueryFingerprint;

/**
 * The three lines a driver writes to record something, in one place.
 *
 * <p>JFR's own idiom is begin, end, {@code shouldCommit}, fill, commit - five
 * steps that have to be in the right order and that are easy to get subtly
 * wrong, most commonly by computing the fields before asking whether anybody
 * wants them. Here the expensive part is the fingerprint, and computing one
 * for every statement when no recording is running would make an observability
 * feature into a cost.
 *
 * <p>So each pair below is: ask for a handle, which is {@code null} when the
 * event is off, and hand it back when the work is done. A {@code null} handle
 * makes every method here do nothing, which is what lets a call site be two
 * lines with no {@code if} around them.
 *
 * <p>Nothing in this class ever sees a parameter value. It is given the SQL
 * text and turns it into a fingerprint itself, deliberately: a call site that
 * could pass something else eventually will.
 */
public final class Observed {

    private Observed() {
    }

    // ---- statements --------------------------------------------------------

    /**
     * Who wants to be told about every statement, or {@code null}.
     *
     * <p>One listener, not a list. A second would be a plugin system, and a
     * plugin system on the statement path is a cost every application pays so
     * that one of them can have two tracers.
     */
    private static volatile StatementListener listener;

    /**
     * Installs the listener, or removes it with {@code null}.
     *
     * <p>Deliberately a static: a driver is reached through
     * {@code DriverManager} and a URL, so there is no object an application
     * could hand this to. Whoever installs one owns it for the process - see
     * {@link StatementListener} for why this exists at all when the events
     * already do.
     */
    public static void listen(StatementListener wanted) {
        listener = wanted;
    }

    /** Whether anything is listening - for a caller that wants to know. */
    public static boolean isListening() {
        return listener != null;
    }

    /**
     * One statement in flight: the recording's handle, the listener's, or
     * both.
     *
     * <p>Both halves are nullable and usually both are absent, which is why
     * {@link #beginQuery()} hands back {@code null} in that case rather than
     * an empty object - the common path allocates nothing.
     */
    public static final class Statement {

        private final SeclumeEvents.Query event;
        private final StatementListener.Span span;

        private Statement(SeclumeEvents.Query event, StatementListener.Span span) {
            this.event = event;
            this.span = span;
        }
    }

    /**
     * A handle, or {@code null} when nobody is recording and nobody is
     * listening - which is what almost every call finds.
     *
     * <p>The kind is wanted here rather than only at the end because a
     * listener opens a span now and a span is named when it opens. The
     * recording needs it at the end, so the drivers pass it twice; the
     * alternative was handing a listener a span it could not name.
     */
    public static Statement beginQuery(String kind) {
        StatementListener watching = listener;
        SeclumeEvents.Query event = new SeclumeEvents.Query();
        boolean recording = event.isEnabled();
        if (!recording && watching == null) {
            return null;
        }
        if (recording) {
            event.begin();
        }
        return new Statement(recording ? event : null,
                watching == null ? null : watching.begin(kind));
    }

    /**
     * Ends the statement and records it if it was slow enough to matter.
     *
     * @param sql the statement text. It does not leave this method: only the
     *            fingerprint is written, and only when the event will
     *            actually be committed
     */
    public static void endQuery(Statement statement, String kind, String sql,
            QueryFingerprint.Dialect dialect, long rows, boolean failed) {
        if (statement == null) {
            return;
        }
        SeclumeEvents.Query event = statement.event;
        // The recording asks first, because it is the one with a threshold:
        // an ordinary statement is under it and costs nothing more than the
        // end() above.
        boolean commits = false;
        if (event != null) {
            event.end();
            commits = event.shouldCommit();
        }
        if (!commits && statement.span == null) {
            // Under the threshold and nobody listening. The fingerprint is
            // never computed for the overwhelming majority of statements,
            // which is the point of asking here rather than earlier.
            return;
        }
        // Computed once for both. A listener sees every statement, so with one
        // installed this is no longer the rare path - which is the cost of
        // tracing and is the caller's decision, not this method's.
        String fingerprint = QueryFingerprint.of(sql, dialect);
        if (commits) {
            event.kind = kind;
            event.fingerprint = fingerprint;
            event.fingerprintId = QueryFingerprint.idOf(sql, dialect);
            event.rows = rows;
            event.failed = failed;
            event.commit();
        }
        if (statement.span != null) {
            statement.span.end(fingerprint, rows, failed);
        }
    }

    /** A server-side plan looked up; cheap enough to record every time. */
    public static void statementCache(String sql, QueryFingerprint.Dialect dialect, boolean hit) {
        SeclumeEvents.StatementCache event = new SeclumeEvents.StatementCache();
        if (!event.isEnabled()) {
            return;
        }
        event.fingerprint = QueryFingerprint.of(sql, dialect);
        event.hit = hit;
        event.commit();
    }

    // ---- connections -------------------------------------------------------

    public static SeclumeEvents.ConnectionOpen beginConnect() {
        SeclumeEvents.ConnectionOpen event = new SeclumeEvents.ConnectionOpen();
        if (!event.isEnabled()) {
            return null;
        }
        event.begin();
        return event;
    }

    /**
     * @param tls what the connection negotiated, or {@code null} without
     *            encryption - written as an empty string, because a missing
     *            value and "no TLS" read the same in a recording and only one
     *            of them is true
     */
    public static void endConnect(SeclumeEvents.ConnectionOpen event, String kind, String server,
            String database, String tls, boolean succeeded) {
        if (event == null) {
            return;
        }
        event.end();
        if (!event.shouldCommit()) {
            return;
        }
        event.kind = kind;
        event.server = server;
        event.database = database;
        event.tls = tls == null ? "" : tls;
        event.succeeded = succeeded;
        event.commit();
    }

    public static SeclumeEvents.TlsHandshake beginHandshake() {
        SeclumeEvents.TlsHandshake event = new SeclumeEvents.TlsHandshake();
        if (!event.isEnabled()) {
            return null;
        }
        event.begin();
        return event;
    }

    public static void endHandshake(SeclumeEvents.TlsHandshake event, String server,
            String stack, String negotiated) {
        if (event == null) {
            return;
        }
        event.end();
        if (!event.shouldCommit()) {
            return;
        }
        event.server = server;
        event.stack = stack;
        event.negotiated = negotiated == null ? "" : negotiated;
        event.commit();
    }

    /** A host of the list was unreachable and the next one was tried. */
    public static void failover(String from, String to, String reason) {
        SeclumeEvents.Failover event = new SeclumeEvents.Failover();
        if (!event.isEnabled()) {
            return;
        }
        event.from = from;
        event.to = to;
        event.reason = reason;
        event.commit();
    }

    // ---- the secret --------------------------------------------------------

    public static SeclumeEvents.CredentialRotation beginCredential() {
        SeclumeEvents.CredentialRotation event = new SeclumeEvents.CredentialRotation();
        if (!event.isEnabled()) {
            return null;
        }
        event.begin();
        return event;
    }

    /**
     * @param expiresInSeconds how long the credential lasts, or -1 when it
     *                         does not expire. Never anything derived from
     *                         the credential itself - not its length, not a
     *                         hash
     */
    public static void endCredential(SeclumeEvents.CredentialRotation event, String provider,
            long expiresInSeconds, boolean succeeded) {
        if (event == null) {
            return;
        }
        event.end();
        if (!event.shouldCommit()) {
            return;
        }
        event.provider = provider;
        event.expiresInSeconds = expiresInSeconds;
        event.succeeded = succeeded;
        event.commit();
    }
}
