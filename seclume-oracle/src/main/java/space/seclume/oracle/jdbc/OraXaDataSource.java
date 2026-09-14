package space.seclume.oracle.jdbc;

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
 * {@link OraDataSource} gets a driver that knows nothing about transaction
 * managers and pays nothing for it. This class is the other door, for an
 * application server that coordinates several databases in one transaction.
 *
 * <p>The account needs two things on the server that an ordinary one does not:
 * {@code execute} on {@code DBMS_XA} - usually granted to {@code PUBLIC} - and
 * the right to read {@code DBA_PENDING_TRANSACTIONS}, without which recovery
 * cannot list what is prepared.
 */
public final class OraXaDataSource implements XADataSource {

    private final OraDataSource source = new OraDataSource();

    /** A fresh XA data source; configure it through {@link #settings()}. */
    public OraXaDataSource() {
    }

    /** The ordinary settings - host, port, service, user, secret source. */
    public OraDataSource settings() {
        return source;
    }

    @Override
    public XAConnection getXAConnection() throws SQLException {
        OraConnection session = (OraConnection) source.getConnection();
        return new DriverXaConnection(session, new OraXaResource(session));
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
