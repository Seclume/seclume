package space.seclume.postgresql.jdbc;

import java.io.PrintWriter;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

import javax.sql.XAConnection;
import javax.sql.XADataSource;

import space.seclume.internal.jdbc.DriverXaConnection;

/**
 * The entry point for distributed transactions - and only for those.
 *
 * <p>Two-phase commit is <b>off unless it is asked for</b>: whoever uses
 * {@link SeclumeDataSource} gets a driver that knows nothing about
 * transaction managers, and pays nothing for it. This class is the other door,
 * for an application server that coordinates several databases in one
 * transaction.
 *
 * <p>It is configured exactly like the ordinary data source, password included
 * - which is to say: not included. The secret comes from a
 * {@code SecretProvider} here as everywhere else.
 *
 * <p><b>One thing on the server:</b> PostgreSQL refuses
 * {@code PREPARE TRANSACTION} unless {@code max_prepared_transactions} is
 * greater than zero, and it is zero by default. The error says so.
 */
public final class SeclumeXaDataSource implements XADataSource {

    private final SeclumeDataSource source = new SeclumeDataSource();

    /** A fresh XA data source; configure it through {@link #settings()}. */
    public SeclumeXaDataSource() {
    }

    /** The ordinary settings - host, port, database, user, secret source. */
    public SeclumeDataSource settings() {
        return source;
    }

    @Override
    public XAConnection getXAConnection() throws SQLException {
        PgConnection session = (PgConnection) source.getConnection();
        return new DriverXaConnection(session, new PgXaResource(session));
    }

    @Override
    public XAConnection getXAConnection(String user, String password) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not take a password as a String - configure a SecretProvider "
                + "on settings() instead. That is the whole point of this library.");
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
        source.setConnectTimeoutMillis(seconds * 1000);
    }

    @Override
    public int getLoginTimeout() {
        return 0;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("seclume does not log through java.util.logging");
    }
}
