package space.seclume.jfr;

import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;
import jdk.jfr.Threshold;

/**
 * What seclume tells the Flight Recorder.
 *
 * <p>Production debugging with no runtime dependency at all: JFR is in the
 * JDK, it is off until somebody starts a recording, and when it is off an
 * event costs an {@code isEnabled()} that the JIT folds away. That fits this
 * project's no-dependencies stance exactly, which is why it is here rather
 * than a logging facade.
 *
 * <p><b>One rule governs every field below, and it has no exceptions.</b> No
 * parameter value and no SQL text. A statement appears as a
 * {@link space.seclume.QueryFingerprint} - the shape with the values taken
 * out - because a recording is written to a file, kept for weeks and passed
 * to whoever is debugging, which is a longer life and a wider audience than
 * anything else this library touches. A JFR event carrying raw SQL would be
 * a leak with a nice user interface.
 *
 * <p>What is deliberately not recorded, beyond the obvious: <b>the database
 * user</b>. It is not a secret, and it is not needed to diagnose anything
 * here - the connection is already identified by server and database - and in
 * a deployment where users are people it is personal data that nobody asked
 * to have in a profiling file.
 *
 * <p>Each class is nested rather than separate because they are one contract
 * read together, and because the rule above is easier to keep when every
 * field in the project's event vocabulary is on one screen.
 */
public final class SeclumeEvents {

    private static final String CATEGORY = "seclume";

    private SeclumeEvents() {
    }

    /** A physical connection being opened - the expensive one. */
    @Name("space.seclume.ConnectionOpen")
    @Label("Connection Open")
    @Category({CATEGORY, "Connection"})
    @Description("A physical database connection being established, including login")
    @StackTrace(false)
    public static final class ConnectionOpen extends Event {

        /** Public and explicit because the Flight Recorder instantiates it. */
        public ConnectionOpen() {
        }

        @Label("Database Kind")
        public String kind;

        @Label("Server")
        @Description("Host and port dialled, never the user or the secret")
        public String server;

        @Label("Database")
        public String database;

        @Label("TLS")
        @Description("Protocol, cipher suite and which stack carried it; empty without TLS")
        public String tls;

        @Label("Succeeded")
        public boolean succeeded;
    }

    /**
     * A TLS handshake.
     *
     * <p>Separate from the connection it belongs to because it is the part
     * that is slow for reasons outside this process - a distant CA, an OCSP
     * lookup, a loaded server - and folding it into the connection time hides
     * exactly that.
     */
    @Name("space.seclume.TlsHandshake")
    @Label("TLS Handshake")
    @Category({CATEGORY, "Connection"})
    @Description("The TLS handshake of one connection")
    @StackTrace(false)
    public static final class TlsHandshake extends Event {

        /** Public and explicit because the Flight Recorder instantiates it. */
        public TlsHandshake() {
        }

        @Label("Server")
        public String server;

        @Label("Stack")
        @Description("jsse or seclume")
        public String stack;

        @Label("Negotiated")
        @Description("Protocol and cipher suite")
        public String negotiated;
    }

    /**
     * A statement, named by its shape.
     *
     * <p>The threshold is what makes this a slow-query event by default: at
     * ten milliseconds an ordinary workload records almost nothing and a
     * problem records itself. Anybody who wants every statement lowers it in
     * the recording settings rather than in the code.
     */
    @Name("space.seclume.Query")
    @Label("Query")
    @Category({CATEGORY, "Statement"})
    @Description("A statement, identified by its fingerprint - never by its text")
    @Threshold("10 ms")
    @StackTrace(false)
    public static final class Query extends Event {

        /** Public and explicit because the Flight Recorder instantiates it. */
        public Query() {
        }

        @Label("Database Kind")
        public String kind;

        @Label("Fingerprint")
        @Description("The statement with every literal and parameter replaced by a question mark")
        public String fingerprint;

        @Label("Fingerprint Id")
        @Description("A stable number for the same shape, for grouping")
        public long fingerprintId;

        @Label("Rows")
        public long rows;

        @Label("Failed")
        public boolean failed;
    }

    /** A connection moving to another server of the list. */
    @Name("space.seclume.Failover")
    @Label("Failover")
    @Category({CATEGORY, "Connection"})
    @Description("A server of the host list could not be reached and the next was tried")
    @StackTrace(false)
    public static final class Failover extends Event {

        /** Public and explicit because the Flight Recorder instantiates it. */
        public Failover() {
        }

        @Label("From")
        public String from;

        @Label("To")
        public String to;

        @Label("Reason")
        @Description("The failure that caused it - a message, never a credential")
        public String reason;
    }

    /**
     * A credential being fetched or replaced.
     *
     * <p>Records that it happened and how long it took. Nothing about what it
     * was: not the secret, not its length, not a hash of it. The provider's
     * kind is configuration and is the only part worth having.
     */
    @Name("space.seclume.CredentialRotation")
    @Label("Credential Rotation")
    @Category({CATEGORY, "Secret"})
    @Description("A secret provider producing a credential")
    @StackTrace(false)
    public static final class CredentialRotation extends Event {

        /** Public and explicit because the Flight Recorder instantiates it. */
        public CredentialRotation() {
        }

        @Label("Provider")
        @Description("The kind of provider, such as file or vault")
        public String provider;

        @Label("Expires In Seconds")
        @Description("How long the credential is valid, or -1 when it does not expire")
        public long expiresInSeconds;

        @Label("Succeeded")
        public boolean succeeded;
    }

    /** Whether a server-side plan was reused. */
    @Name("space.seclume.StatementCache")
    @Label("Statement Cache")
    @Category({CATEGORY, "Statement"})
    @Description("A lookup in the server-side statement cache")
    @StackTrace(false)
    public static final class StatementCache extends Event {

        /** Public and explicit because the Flight Recorder instantiates it. */
        public StatementCache() {
        }

        @Label("Fingerprint")
        public String fingerprint;

        @Label("Hit")
        public boolean hit;
    }
}
