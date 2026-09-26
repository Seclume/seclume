package space.seclume.oracle.jdbc;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

import space.seclume.oracle.OracleSession;

/**
 * The JDBC driver for Oracle.
 *
 * <p>It registers with the {@link DriverManager} as soon as the class is
 * loaded - through {@code META-INF/services/java.sql.Driver} that happens by
 * itself.
 *
 * <p>{@link #connect(String, Properties)} deliberately does not accept a
 * {@code password}. The signature allows it, this driver does not: a password
 * inside a {@code Properties} object is a {@code String} on the heap.
 */
public final class OraDriver implements Driver {

    private static final OraDriver INSTANCE = new OraDriver();

    /** The ServiceLoader needs it public; the one instance is what gets used. */
    public OraDriver() {
    }

    static {
        try {
            DriverManager.registerDriver(INSTANCE);
        } catch (SQLException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    public Connection connect(String url, Properties properties) throws SQLException {
        if (!acceptsURL(url)) {
            // The DriverManager asks around; null means "not mine".
            return null;
        }
        OracleSession.Settings settings = OraUrl.settings(url, properties);
        return new OraConnection(space.seclume.internal.TrustChoice.using(
                space.seclume.internal.TrustChoice.of(url, properties),
                () -> space.seclume.internal.Transports.using(
                        space.seclume.internal.Transports.option(url, properties),
                        () -> OracleSession.open(settings))), url);
    }

    @Override
    public boolean acceptsURL(String url) {
        return OraUrl.accepts(url);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties properties) {
        return new DriverPropertyInfo[] {
            info("user", "the database user", true),
            info("provider", "where the password comes from: file, env-file, unix-socket, "
                    + "process, dpapi, credential-manager", true),
            info("path", "file or socket the provider reads", false),
            info("key", "entry name for the env-file provider", false),
            info("target", "target name for the Windows credential manager", false),
            info("entropy", "second factor for DPAPI", false),
            info("command", "command for the process provider", false),
            info("connectTimeout", "milliseconds to wait for the socket", false),
        };
    }

    private static DriverPropertyInfo info(String name, String description, boolean required) {
        DriverPropertyInfo property = new DriverPropertyInfo(name, null);
        property.description = description;
        property.required = required;
        return property;
    }

    @Override
    public int getMajorVersion() {
        return 0;
    }

    @Override
    public int getMinorVersion() {
        return 1;
    }

    /**
     * No - and that is not modesty. The driver covers a part of JDBC and
     * refuses the rest openly.
     */
    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("seclume does not use java.util.logging");
    }
}
