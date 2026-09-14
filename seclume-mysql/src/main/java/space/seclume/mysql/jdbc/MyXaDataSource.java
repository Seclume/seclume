package space.seclume.mysql.jdbc;

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
 * {@link MyDataSource} gets a driver that knows nothing about transaction
 * managers and pays nothing for it. This class is the other door, for an
 * application server that coordinates several databases in one transaction.
 *
 * <p>It is configured exactly like the ordinary data source, password included
 * - which is to say: not included. The secret comes from a
 * {@code SecretProvider} here as everywhere else.
 */
public final class MyXaDataSource implements XADataSource {

    private final MyDataSource source = new MyDataSource();

    /** A fresh XA data source; configure it through {@link #settings()}. */
    public MyXaDataSource() {
    }

    /** The ordinary settings - host, port, database, user, secret source. */
    public MyDataSource settings() {
        return source;
    }

    @Override
    public XAConnection getXAConnection() throws SQLException {
        MyConnection session = (MyConnection) source.getConnection();
        return new DriverXaConnection(session, new MyXaResource(session));
    }

    @Override
    public XAConnection getXAConnection(String user, String password) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not take a password as a String - configure a SecretProvider "
                + "on settings() instead. That is the whole point of this library.");
    }

    @Override
    public PrintWriter getLogWriter() {
        return source.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) {
        source.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) {
        source.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() {
        return source.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("seclume does not log through java.util.logging");
    }
}
