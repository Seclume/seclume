/**
 * The core of seclume: secret sources, off-heap memory handling, and the
 * cryptography the four database handshakes need.
 *
 * <p>No third-party dependencies - {@code requires} names JDK modules only.
 * The driver modules depend on this and nothing else.
 */
module seclume.core {

    // Only for the shared JDBC scaffolding; the core itself speaks no SQL.
    requires transitive java.sql;

    // Flight Recorder events. A JDK module, so this adds no dependency in the
    // sense that matters - and it is why the observability is JFR rather than
    // a logging facade somebody would have to bring along.
    // Transitive because the event types appear in the signatures Observed
    // hands the drivers; without it every driver module would have to
    // require jdk.jfr to name a type it only passes back.
    requires transitive jdk.jfr;

    /** The small public surface every driver shares. */
    exports space.seclume;
    exports space.seclume.crypto;
    exports space.seclume.secret;

    // Internal building blocks the driver modules need (randomness, encoding,
    // off-heap I/O). Not a stable contract for applications.
    exports space.seclume.internal;
    // Another way of reaching a server may arrive on the class path; this
    // library opens sockets and nothing else. See TransportProvider.
    uses space.seclume.internal.TransportProvider;

    // The TLS 1.3 client of our own. Exported because the
    // drivers will need it; not a contract for applications, and not a
    // replacement for JSSE, which stays the default.
    exports space.seclume.tls;
    exports space.seclume.internal.jdbc;

    /** The Flight Recorder events, so the drivers and the pool can raise them. */
    exports space.seclume.jfr;
}
