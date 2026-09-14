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

    /** The small public surface every driver shares. */
    exports space.seclume;
    exports space.seclume.crypto;
    exports space.seclume.secret;

    // Internal building blocks the driver modules need (randomness, encoding,
    // off-heap I/O). Not a stable contract for applications.
    exports space.seclume.internal;
    exports space.seclume.internal.jdbc;
}
