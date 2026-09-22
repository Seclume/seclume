package space.seclume.sqlserver.jdbc;

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
import java.time.Instant;

import space.seclume.secret.ExpiringCredentials;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.sqlserver.tds.TdsSession;

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
public final class TdsDataSource implements DataSource, ExpiringCredentials {

    private final Map<String, String> properties = new LinkedHashMap<>();
    private String host = "127.0.0.1";
    private int port = TdsUrl.DEFAULT_PORT;
    private String database = "master";
    private String user;
    private String applicationName = "seclume";
    private int connectTimeoutMillis = 10_000;
    private boolean trustServerCertificate;
    private SecretProvider secret;
    private space.seclume.tls.ClientIdentity identity;
    /**
     * Which TDS version, and therefore where TLS sits. {@code 7.4} wraps the
     * handshake inside TDS packets; {@code 8.0} is TLS from the first byte,
     * which is the only version this library's own TLS stack can carry.
     */
    private space.seclume.sqlserver.tds.TdsVersion tdsVersion =
            space.seclume.sqlserver.tds.TdsVersion.TDS_7_4;
    /**
     * Which TLS implementation carries the connection; {@code jsse} by
     * default. A separate decision from how much encryption is asked for -
     * see {@link space.seclume.internal.jdbc.TlsStack}.
     */
    private space.seclume.internal.jdbc.TlsStack tlsStack =
            space.seclume.internal.jdbc.TlsStack.JSSE;
    private PrintWriter logWriter;
    private HostList hosts;
    private long maxResultBytes;
    private long maxResultRows;

    /** Frameworks build a DataSource through the no-argument constructor. */
    public TdsDataSource() {
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Several servers for the same database: {@code db1:1433,db2:1433}.
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
     * Accepts any TLS certificate. Only for a test server with a self-signed
     * one - it gives up the protection against a man in the middle, and the
     * name says so plainly so that nobody switches it on by accident.
     */
    public void setTrustServerCertificate(boolean trust) {
        this.trustServerCertificate = trust;
    }

    /** The provider directly, when the application builds it itself. */
    public void setSecretProvider(SecretProvider secret) {
        this.secret = secret;
    }

    /**
     * A client identity directly, when the application builds it itself.
     *
     * <p>The alternative is to describe one in the properties -
     * {@code clientCert} plus {@code clientKey-provider} and its settings -
     * which is what {@link space.seclume.tls.ClientIdentities} reads.
     */
    public void setClientIdentity(space.seclume.tls.ClientIdentity identity) {
        this.identity = identity;
    }

    /** {@code 7.4} or {@code 8.0} - see the field. */
    public void setTds(String version) throws SQLException {
        this.tdsVersion = space.seclume.sqlserver.tds.TdsVersion.of(version);
    }

    public String getTds() {
        return tdsVersion == space.seclume.sqlserver.tds.TdsVersion.TDS_8_0 ? "8.0" : "7.4";
    }

    public void setTlsStack(String stack) throws SQLException {
        try {
            this.tlsStack = space.seclume.internal.jdbc.TlsStack.of(stack);
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
    }

    public String getTlsStack() {
        return tlsStack.name().toLowerCase(java.util.Locale.ROOT);
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
        TdsSession.Settings settings = TdsUrl.settings(url, null);
        this.host = settings.host();
        this.port = settings.port();
        this.database = settings.database();
        this.user = settings.user();
        this.secret = settings.secret();
        this.applicationName = settings.applicationName();
        this.connectTimeoutMillis = settings.connectTimeoutMillis();
        this.trustServerCertificate = settings.trustServerCertificate();
        this.hosts = settings.hosts();
        // Everything the URL can say, or the same text means two different
        // things depending on which of the two doors it came through. These
        // three were missing, which is why a client certificate could be
        // configured in a URL and not in a DataSource - the door Spring Boot
        // uses.
        this.tdsVersion = settings.tdsVersion();
        this.tlsStack = settings.tlsStack();
        this.identity = settings.identity();
    }

    @Override
    public Connection getConnection() throws SQLException {
        if (user == null || user.isBlank()) {
            throw new SQLException("no user configured - seclume does not guess it");
        }
        SecretProvider provider = resolvedSecret();
        TdsSession.Settings settings = new TdsSession.Settings(host, port, database, user,
                provider, applicationName, connectTimeoutMillis, trustServerCertificate,
                hosts != null ? hosts : HostList.of(host, port),
                ResultLimit.of(maxResultBytes, maxResultRows), tdsVersion, tlsStack,
                resolvedIdentity());
        return new TdsConnection(TdsSession.open(settings),
                TdsUrl.PREFIX + "//" + host + ":" + port + "/" + database);
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

    /**
     * When the credential this data source hands out stops working.
     *
     * <p>Only passed on: the answer belongs to the secret provider, and only a
     * dynamic one has an answer at all. A password in a file says
     * {@code null}, which every caller has to read as "it does not expire".
     *
     * <p>It exists so a pool can retire connections before their credential
     * lapses rather than after. The pool itself knows nothing about secret
     * providers and is not going to; the Spring starter joins the two.
     */
    @Override
    public Instant credentialsValidUntil() {
        SecretProvider provider = resolvedSecret();
        return provider instanceof ExpiringCredentials expiring
                ? expiring.credentialsValidUntil() : null;
    }

    /**
     * The provider in use, built from the properties if none was set.
     *
     * <p>Built <b>once</b> and kept. It used to be built inside
     * {@code getConnection}, which was harmless for a file and wrong for
     * anything with a lease: a fresh Vault provider per connection means a
     * fresh database user per connection, each with a lease of its own, and a
     * pool of sixteen leaves hundreds behind. One provider per data source is
     * also what the Spring path always did.
     */
    private synchronized SecretProvider resolvedSecret() {
        if (secret == null) {
            secret = SecretProviders.of(properties);
        }
        return secret;
    }

    /**
     * The client identity in use, built from the properties if none was set.
     *
     * <p>Built once, like the secret provider and for a sharper version of the
     * same reason: the private key is loaded into native memory and held
     * there, so one per data source rather than one per connection.
     */
    private synchronized space.seclume.tls.ClientIdentity resolvedIdentity() {
        if (identity == null) {
            identity = space.seclume.tls.ClientIdentities.of(properties);
        }
        return identity;
    }
}
