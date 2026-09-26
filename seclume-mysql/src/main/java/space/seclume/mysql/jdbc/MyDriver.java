package space.seclume.mysql.jdbc;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

import space.seclume.mysql.MySession;

/**
 * The JDBC driver for MySQL and MariaDB.
 *
 * <p>It registers with the {@link DriverManager} as soon as the class is
 * loaded - through {@code META-INF/services/java.sql.Driver} that happens by
 * itself.
 *
 * <p>{@link #connect(String, Properties)} deliberately does not accept a
 * {@code password}. The signature allows it, this driver does not: a password
 * inside a {@code Properties} object is a {@code String} on the heap.
 */
public final class MyDriver implements Driver {

    private static final MyDriver INSTANCE = new MyDriver();

    /** The ServiceLoader needs it public; the one instance is what gets used. */
    public MyDriver() {
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
        MySession.Settings settings = MyUrl.settings(url, properties);
        boolean loadDataLocal = MyUrl.loadDataLocal(url, properties);
        return new MyConnection(space.seclume.internal.TrustChoice.using(
                space.seclume.internal.TrustChoice.of(url, properties),
                () -> space.seclume.internal.Transports.using(
                        space.seclume.internal.Transports.option(url, properties),
                        () -> MySession.allowingLocalData(loadDataLocal,
                                () -> MySession.open(settings)))), url)
                .rewriteBatchedInserts(MyUrl.rewriteBatchedInserts(url, properties));
    }

    @Override
    public boolean acceptsURL(String url) {
        return MyUrl.accepts(url);
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
            info("applicationName", "shown in the connection attributes", false),
            info("connectTimeout", "milliseconds to wait for the socket", false),
            info("allowPublicKeyRetrieval",
                    "let the driver ask an unencrypted server for its RSA public key "
                    + "(caching_sha2_password full authentication) - off by default, because "
                    + "a man in the middle would answer that question too", false),
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
