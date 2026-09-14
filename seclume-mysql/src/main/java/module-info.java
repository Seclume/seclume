/**
 * The driver for MySQL and MariaDB: protocol 4.1, the login methods and the
 * JDBC surface on top of them.
 *
 * <p>{@code provides java.sql.Driver} is the reason a Spring project has to do
 * nothing beyond adding the dependency - the {@code DriverManager} finds the
 * driver by itself, on the module path here and on the class path via
 * {@code META-INF/services}.
 */
module seclume.mysql {

    // transitive: MySession and MyException are part of the API and throw SQLException.
    requires transitive java.sql;
    requires transitive seclume.core;

    exports space.seclume.mysql;
    exports space.seclume.mysql.jdbc;
    exports space.seclume.mysql.wire;

    provides java.sql.Driver with space.seclume.mysql.jdbc.MyDriver;
}
