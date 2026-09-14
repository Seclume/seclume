package space.seclume.oracle.jdbc;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.sql.DataSource;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.oracle.OracleSession;

/**
 * A {@link DataSource} without a pool - one connection per call.
 *
 * <p>This is the way Spring and other frameworks tie a driver in. The pool sits
 * on top of it; this class then stays what the pool uses to get a new
 * connection.
 *
 * <p>There is deliberately no {@code setPassword} here. A setter for a password
 * would be a {@code String} living as long as the {@code DataSource} - that is,
 * the whole application. Instead:
 * {@link #setSecretProvider(SecretProvider)} or {@link #setProperty} with
 * {@code provider} and {@code path}.
 */
public final class OraDataSource implements DataSource {

    private final Map<String, String> properties = new LinkedHashMap<>();
    private String host = "127.0.0.1";
    private int port = OraUrl.DEFAULT_PORT;
    private String service;
    private String user;
    private int connectTimeoutMillis = 10_000;
    private SecretProvider secret;
    private PrintWriter logWriter;
    private HostList hosts;
    private long maxResultBytes;
    private long maxResultRows;

    /** Frameworks build a DataSource through the no-argument constructor. */
    public OraDataSource() {
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Several servers for the same database: {@code db1:1521,db2:1521}.
     *
     * <p>Failover at the moment of connecting - if a server cannot be reached,
     * the next one is asked, and the one that answered is asked first next
     * time. A rejected password is <b>not</b> a reason to move on; see
     * {@link HostList}.
     *
     * <p>Off unless it is set: one host, one server, exactly as before.
     */
    public void setHosts(String list) {
        this.hosts = HostList.parse(list, port);
        this.host = hosts.first().host();
        this.port = hosts.first().port();
    }

    /** Oracle connects to a service, not to a database. */
    public void setService(String service) {
        this.service = service;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public void setConnectTimeoutMillis(int millis) {
        this.connectTimeoutMillis = millis;
    }

    /**
     * How large a single result may get before the driver refuses it.
     *
     * <p>Off by default. Set it, and a forgotten {@code where} ends in a
     * {@link java.sql.SQLException} that names the statement instead of an
     * {@code OutOfMemoryError} that takes the whole application with it. See
     * {@link ResultLimit}.
     */
    public void setMaxResultBytes(long maxResultBytes) {
        this.maxResultBytes = maxResultBytes;
    }

    /** The same for the number of rows - unlike {@code setMaxRows} it says so. */
    public void setMaxResultRows(long maxResultRows) {
        this.maxResultRows = maxResultRows;
    }


    /** The provider directly, when the application builds it itself. */
    public void setSecretProvider(SecretProvider secret) {
        this.secret = secret;
    }

    /** Provider settings as in {@code application.properties}. */
    public void setProperty(String key, String value) {
        properties.put(key, value);
    }

    /**
     * Takes over a whole URL, so that the same text means the same thing in
     * the driver and in the {@code DataSource}.
     */
    public void setUrl(String url) throws SQLException {
        OracleSession.Settings settings = OraUrl.settings(url, null);
        this.host = settings.host();
        this.port = settings.port();
        this.service = settings.service();
        this.user = settings.user();
        this.secret = settings.secret();
        this.connectTimeoutMillis = settings.connectTimeoutMillis();
        this.hosts = settings.hosts();
    }

    @Override
    public Connection getConnection() throws SQLException {
        if (user == null || user.isBlank()) {
            throw new SQLException("no user configured - seclume does not guess it");
        }
        SecretProvider provider = secret != null ? secret : SecretProviders.of(properties);
        if (service == null || service.isBlank()) {
            throw new SQLException("no service configured - Oracle connects to a service");
        }
        OracleSession.Settings settings = new OracleSession.Settings(host, port, service,
                user, provider, connectTimeoutMillis,
                hosts != null ? hosts : HostList.of(host, port),
                ResultLimit.of(maxResultBytes, maxResultRows));
        return new OraConnection(OracleSession.open(settings),
                OraUrl.PREFIX + "//" + host + ":" + port + "/" + service);
    }

    /**
     * The path with user and password - refused, and with the reason given.
     * Anyone who needs it needs a different library.
     */
    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "getConnection(user, password) takes the password as a String, which stays "
                + "in the heap until the garbage collector happens to overwrite it - the one "
                + "thing seclume exists to prevent. Configure a secret provider and call "
                + "getConnection().");
    }

    @Override
    public PrintWriter getLogWriter() {
        return logWriter;
    }

    @Override
    public void setLogWriter(PrintWriter out) {
        this.logWriter = out;
    }

    @Override
    public void setLoginTimeout(int seconds) {
        this.connectTimeoutMillis = seconds * 1000;
    }

    @Override
    public int getLoginTimeout() {
        return connectTimeoutMillis / 1000;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("seclume does not use java.util.logging");
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("not a wrapper for " + iface.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this);
    }
}
