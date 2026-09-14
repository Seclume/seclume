/**
 * The driver for SQL Server: TDS 7.4, the login through TLS inside TDS, and
 * the JDBC surface on top of it.
 *
 * <p>{@code provides java.sql.Driver} is the reason a Spring project has to do
 * nothing beyond adding the dependency - the {@code DriverManager} finds the
 * driver by itself, on the module path here and on the class path via
 * {@code META-INF/services}.
 */
module seclume.sqlserver {

    // transitive: TdsSession is part of the API and throws SQLException.
    requires transitive java.sql;
    requires transitive seclume.core;

    exports space.seclume.sqlserver.tds;
    exports space.seclume.sqlserver.auth;
    exports space.seclume.sqlserver.jdbc;

    provides java.sql.Driver with space.seclume.sqlserver.jdbc.TdsDriver;
}
