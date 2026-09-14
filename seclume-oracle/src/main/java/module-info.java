/**
 * The driver for Oracle: the NS and TTC layers, the login, and the JDBC
 * surface on top of them.
 *
 * <p>{@code provides java.sql.Driver} is the reason a Spring project has to do
 * nothing beyond adding the dependency - the {@code DriverManager} finds the
 * driver by itself, on the module path here and on the class path via
 * {@code META-INF/services}.
 */
module seclume.oracle {

    // transitive: OracleSession is part of the API and throws SQLException.
    requires transitive java.sql;
    requires transitive seclume.core;

    exports space.seclume.oracle;
    exports space.seclume.oracle.auth;
    exports space.seclume.oracle.net;
    exports space.seclume.oracle.jdbc;

    provides java.sql.Driver with space.seclume.oracle.jdbc.OraDriver;
}
