/**
 * The PostgreSQL driver: wire protocol 3.0, SCRAM login and the JDBC surface
 * on top of it.
 *
 * <p>{@code provides java.sql.Driver} is the reason a Spring project has to do
 * nothing beyond adding the dependency - the {@code DriverManager} finds the
 * driver by itself, on the module path here and on the class path via
 * {@code META-INF/services}.
 */
module seclume.postgresql {

    // transitive: PgSession and PgException are part of the API and throw SQLException.
    requires transitive java.sql;
    requires transitive seclume.core;

    exports space.seclume.postgresql;
    exports space.seclume.postgresql.jdbc;

    provides java.sql.Driver with space.seclume.postgresql.jdbc.SeclumeDriver;
}
