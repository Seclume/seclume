package space.seclume.sqlserver.jdbc;

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
 * {@link TdsDataSource} gets a driver that knows nothing about transaction
 * managers and pays nothing for it. This class is the other door, for an
 * application server that coordinates several databases in one transaction.
 *
 * <p>SQL Server brings the {@code sp_xa_*} procedures along since 2017 CU16,
 * so nothing has to be installed on the server any more - which used to mean
 * copying a DLL and running a script. What the server does need is its
 * distributed transaction coordinator; on Linux that is off by default and is
 * switched on with {@code mssql-conf} ({@code network.rpcport} and
 * {@code distributedtransaction.servertcpport}), followed by a restart.
 *
 * <p><b>Two connections per XA connection.</b> The XA commands cannot run on
 * the session that is inside the transaction - it would wait for itself - so
 * this opens a second one and closes it again with the first.
 */
public final class TdsXaDataSource implements XADataSource {

    private final TdsDataSource source = new TdsDataSource();

    /** A fresh XA data source; configure it through {@link #settings()}. */
    public TdsXaDataSource() {
    }

    /** The ordinary settings - host, port, database, user, secret source. */
    public TdsDataSource settings() {
        return source;
    }

    @Override
    public XAConnection getXAConnection() throws SQLException {
        TdsConnection session = (TdsConnection) source.getConnection();
        TdsConnection control = (TdsConnection) source.getConnection();
        try {
            return new DriverXaConnection(session, new TdsXaResource(session, control), control);
        } catch (SQLException e) {
            control.close();
            session.close();
            throw e;
        }
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
