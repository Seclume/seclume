package space.seclume.helidon;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;

/** A driver for {@code jdbc:seclume:stub:} whose connections answer what a pool asks. */
final class StubDriver implements Driver {
    final List<String> urls = new CopyOnWriteArrayList<>();

    /** One per test JVM, registered once. */
    static final StubDriver INSTANCE = register();

    private static StubDriver register() {
        StubDriver driver = new StubDriver();
        try {
            DriverManager.registerDriver(driver);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return driver;
    }

    @Override
    public Connection connect(String url, Properties info) {
        if (!acceptsURL(url)) {
            return null;
        }
        urls.add(url);
        boolean[] closed = {false};
        return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "isValid" -> !closed[0];
                    case "isClosed" -> closed[0];
                    case "close", "abort" -> {
                        closed[0] = true;
                        yield null;
                    }
                    case "unwrap" -> throw new SQLException("not a wrapper");
                    case "getAutoCommit" -> true;
                    case "isReadOnly" -> false;
                    case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                    case "getCatalog", "getSchema", "getWarnings" -> null;
                    case "getHoldability" -> java.sql.ResultSet.HOLD_CURSORS_OVER_COMMIT;
                    case "getNetworkTimeout" -> 0;
                    case "isWrapperFor" -> false;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    case "toString" -> "StubConnection";
                    case "setAutoCommit", "setReadOnly", "setTransactionIsolation", "clearWarnings",
                            "setCatalog", "setSchema", "rollback", "commit", "setHoldability",
                            "setNetworkTimeout" -> null;
                    default -> throw new SQLFeatureNotSupportedException(method.getName());
                });
    }

    @Override
    public boolean acceptsURL(String url) {
        return url != null && url.startsWith("jdbc:seclume:stub:");
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        return new DriverPropertyInfo[0];
    }

    @Override
    public int getMajorVersion() {
        return 1;
    }

    @Override
    public int getMinorVersion() {
        return 0;
    }

    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("none");
    }
}

