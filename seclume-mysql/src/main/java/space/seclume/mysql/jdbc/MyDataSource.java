package space.seclume.mysql.jdbc;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.sql.DataSource;

import space.seclume.mysql.MySession;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * A {@link DataSource} without a pool - one connection per call.
 *
 * <p>This is the way Spring and other frameworks tie a driver in. The pool
 * comes on top of it in stage 7; this class then stays what the pool uses to
 * get a new connection.
 *
 * <p>There is deliberately no {@code setPassword} here. A setter for a password
 * would be a {@code String} living as long as the {@code DataSource} - that is,
 * the whole application. Instead:
 * {@link #setSecretProvider(SecretProvider)} or {@link #setProperty} with
 * {@code provider} and {@code path}.
 */
public final class MyDataSource implements DataSource {

    private final Map<String, String> properties = new LinkedHashMap<>();
    private String host = "127.0.0.1";
    private int port = 3306;
    private String database;
    private String user;
    private String applicationName = "seclume";
    private int connectTimeoutMillis = 10_000;
    private boolean allowPublicKeyRetrieval;
    private SecretProvider secret;
    private PrintWriter logWriter;
    private HostList hosts;
    private long maxResultBytes;
    private long maxResultRows;

    /** Frameworks build a DataSource through the no-argument constructor. */
    public MyDataSource() {
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Several servers for the same database: {@code db1:3306,db2:3306}.
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

    public void setDatabase(String database) {
        this.database = database;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
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


    /**
     * Allows asking an unencrypted server for its public key
     * ({@code caching_sha2_password}, full path). Defaulted to {@code false}
     * for good reason: a man in the middle would answer that question just as
     * happily.
     */
    public void setAllowPublicKeyRetrieval(boolean allow) {
        this.allowPublicKeyRetrieval = allow;
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
        MySession.Settings settings = MyUrl.settings(url, null);
        this.host = settings.host();
        this.port = settings.port();
        this.database = settings.database();
        this.user = settings.user();
        this.secret = settings.secret();
        this.applicationName = settings.applicationName();
        this.connectTimeoutMillis = settings.connectTimeoutMillis();
        this.allowPublicKeyRetrieval = settings.allowPublicKeyRetrieval();
        this.hosts = settings.hosts();
        this.tls = settings.tls();
    }

    /**
     * How much encryption the connection asks for; {@code prefer} by default.
     *
     * <p>Named rather than a boolean, because „encrypted" and „authenticated"
     * are two different promises: only {@code verify-full} checks who is at the
     * other end. See {@link TlsMode}.
     */
    private TlsMode tls = TlsMode.PREFER;

    public void setTls(String mode) throws SQLException {
        this.tls = TlsMode.of(mode);
    }

    public String getTls() {
        return tls.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
    }

    @Override
    public Connection getConnection() throws SQLException {
        if (database == null || database.isBlank()) {
            throw new SQLException("no database configured");
        }
        if (user == null || user.isBlank()) {
            throw new SQLException("no user configured - seclume does not guess it");
        }
        SecretProvider provider = secret != null ? secret : SecretProviders.of(properties);
        MySession.Settings settings = new MySession.Settings(host, port, database, user,
                provider, applicationName, connectTimeoutMillis, allowPublicKeyRetrieval,
                hosts != null ? hosts : HostList.of(host, port),
                ResultLimit.of(maxResultBytes, maxResultRows), tls);
        return new MyConnection(MySession.open(settings),
                MyUrl.PREFIX + "//" + host + ":" + port + "/" + database);
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
