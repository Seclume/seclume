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

    /** A handle, or {@code null} when nobody is recording. */
    public static SeclumeEvents.Query beginQuery() {
        SeclumeEvents.Query event = new SeclumeEvents.Query();
        if (!event.isEnabled()) {
            return null;
        }
        event.begin();
        return event;
    }

    /**
     * Ends the statement and records it if it was slow enough to matter.
     *
     * @param sql the statement text. It does not leave this method: only the
     *            fingerprint is written, and only when the event will
     *            actually be committed
     */
    public static void endQuery(SeclumeEvents.Query event, String kind, String sql,
            QueryFingerprint.Dialect dialect, long rows, boolean failed) {
        if (event == null) {
            return;
        }
        event.end();
        if (!event.shouldCommit()) {
            // Under the threshold. The fingerprint is never computed for the
            // overwhelming majority of statements, which is the point of
            // asking here rather than earlier.
            return;
        }
        event.kind = kind;
        event.fingerprint = QueryFingerprint.of(sql, dialect);
        event.fingerprintId = QueryFingerprint.idOf(sql, dialect);
        event.rows = rows;
        event.failed = failed;
        event.commit();
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
