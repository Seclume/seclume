package space.seclume.bench;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

import javax.sql.DataSource;

/**
 * The plainest {@code DataSource} there is: a URL and a {@code DriverManager}.
 *
 * <p>Only here so that both pools see the same vendor driver with the same
 * settings. Anything cleverer would end up being measured.
 */
final class DriverManagerDataSource implements DataSource {

    private final String url;
    private final Properties properties;

    DriverManagerDataSource(String url, Properties properties) {
        this.url = url;
        this.properties = properties;
    }

    @Override
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(url, properties);
    }

    @Override
    public Connection getConnection(String user, String password) throws SQLException {
        Properties copy = new Properties();
        copy.putAll(properties);
        copy.setProperty("user", user);
        copy.setProperty("password", password);
        return DriverManager.getConnection(url, copy);
    }

    @Override
    public PrintWriter getLogWriter() {
        return null;
    }

    @Override
    public void setLogWriter(PrintWriter out) {
    }

    @Override
    public void setLoginTimeout(int seconds) {
    }

    @Override
    public int getLoginTimeout() {
        return 0;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException(
                "this data source does not log through java.util.logging");
    }

    @Override
    public <T> T unwrap(Class<T> type) throws SQLException {
        if (type.isInstance(this)) {
            return type.cast(this);
        }
        throw new SQLException("not a wrapper for " + type);
    }

    @Override
    public boolean isWrapperFor(Class<?> type) {
        return type.isInstance(this);
    }
}
