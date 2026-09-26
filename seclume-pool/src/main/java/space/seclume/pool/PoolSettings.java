package space.seclume.pool;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * The settings of a pool.
 *
 * <p>A mutable object with setters, because that is exactly how Spring binds -
 * and because the pool reads the values once at startup and never again. The
 * defaults are the ones most applications get by with.
 *
 * <p>What is <b>not</b> here matters as much as what is: no password and no
 * configuration of a secret source. The pool receives a {@code DataSource} and
 * asks it; where that takes its secret from is none of its business. Which is
 * why {@link #toString()} cannot give anything away either.
 */
public final class PoolSettings {

    private String name = "seclume-pool";
    private int maximumPoolSize = 10;
    private int minimumIdle = -1;
    private Duration connectionTimeout = Duration.ofSeconds(30);
    private Duration idleTimeout = Duration.ofMinutes(10);
    private Duration maxLifetime = Duration.ofMinutes(30);
    /**
     * How long before a dynamic credential expires a connection is retired.
     *
     * <p>Only has an effect when the underlying {@code DataSource} reports an
     * expiry at all - see {@code ExpiringCredentials}. A static password in a
     * file never does, and then this setting does nothing.
     *
     * <p>A minute is generous on purpose. The cost of retiring early is one
     * handshake; the cost of retiring late is an authentication failure in a
     * working application, and those two are not the same size.
     */
    private Duration credentialMargin = Duration.ofMinutes(1);

    /**
     * How far the retirements are spread out ahead of the margin.
     *
     * <p><b>Because a pool opens its connections in a burst.</b> Ten
     * connections made in the same second by the same credential share an
     * expiry to the second, so without this they all reach their deadline in
     * one housekeeping round, are all retired at once, and the pool is briefly
     * a fraction of its size - at which point every waiting caller pays a full
     * handshake, and with Vault an HTTP round trip as well. The failure is not
     * an outage and it is exactly the sort of thing that shows up as an
     * unexplained latency spike on the hour.
     *
     * <p>So each connection's deadline is drawn at random from a window of
     * this length <b>before</b> the margin, and the cohort retires over a
     * stretch instead of in one go. Only ever earlier, never later: the margin
     * remains the latest moment a connection may still be in use.
     *
     * <p>Defaults to the margin, which makes the window twice the margin wide
     * in total. Zero puts the old behaviour back.
     */
    private Duration credentialSpread = Duration.ofMinutes(1);

    /**
     * Where the pool learns when the current credential stops working.
     *
     * <p>{@code null} by default, and then nothing about this pool changes -
     * which is the right default for a password in a file, and keeps this
     * module free of any knowledge of seclume's secret sources.
     *
     * <p>Set it to {@code () -> dataSource.credentialsValidUntil()} for a
     * driver {@code DataSource} that implements
     * {@code space.seclume.secret.ExpiringCredentials}; the Spring starter
     * does that itself. It is asked once per connection opened, not per
     * handout, so it may do real work - though a provider that fetches on
     * every call would be the wrong kind of provider anyway.
     */
    private Supplier<Instant> credentialExpiry;
    private Duration keepaliveTime = Duration.ZERO;
    private Duration shutdownTimeout = Duration.ofSeconds(10);
    private Supplier<java.util.Map<String, String>> sessionContext;
    private Duration validationTimeout = Duration.ofSeconds(5);
    private Duration validationBypassWindow = Duration.ofMillis(500);
    private Duration leakDetectionThreshold = Duration.ZERO;
    private boolean warmup;
    private int statementCacheSize = 64;
    private boolean renewBrokenConnections = true;

    /** Defaults; frameworks fill in from here through the setters. */
    public PoolSettings() {
    }

    public String getName() {
        return name;
    }

    /** Shows up in the housekeeping thread names - helpful in a thread dump. */
    public void setName(String name) {
        this.name = name;
    }

    public int getMaximumPoolSize() {
        return maximumPoolSize;
    }

    public void setMaximumPoolSize(int maximumPoolSize) {
        if (maximumPoolSize < 1) {
            throw new IllegalArgumentException("maximumPoolSize must be at least 1");
        }
        this.maximumPoolSize = maximumPoolSize;
    }

    /** How many connections should stand ready; by default as many as the maximum. */
    public int getMinimumIdle() {
        return minimumIdle < 0 ? maximumPoolSize : Math.min(minimumIdle, maximumPoolSize);
    }

    public void setMinimumIdle(int minimumIdle) {
        if (minimumIdle < 0) {
            throw new IllegalArgumentException("minimumIdle must not be negative");
        }
        this.minimumIdle = minimumIdle;
    }

    /** How long {@code getConnection()} waits for a free connection. */
    public Duration getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(Duration connectionTimeout) {
        this.connectionTimeout = requirePositive(connectionTimeout, "connectionTimeout");
    }

    /** When an unused connection beyond {@link #getMinimumIdle()} is let go. */
    public Duration getIdleTimeout() {
        return idleTimeout;
    }

    public void setIdleTimeout(Duration idleTimeout) {
        this.idleTimeout = requireNonNegative(idleTimeout, "idleTimeout");
    }

    /**
     * When a connection is replaced even though it is healthy.
     *
     * <p>This is not cosmetic: databases, firewalls and load balancers cut old
     * connections eventually on their own, and a connection the pool replaces
     * on schedule bothers nobody - one the server throws away bothers a
     * user.
     */
    public Duration getMaxLifetime() {
        return maxLifetime;
    }

    public void setMaxLifetime(Duration maxLifetime) {
        this.maxLifetime = requireNonNegative(maxLifetime, "maxLifetime");
    }

    /** @see #credentialMargin */
    public Duration getCredentialMargin() {
        return credentialMargin;
    }

    /** @see #credentialSpread */
    public Duration getCredentialSpread() {
        return credentialSpread;
    }

    /** @see #credentialSpread */
    public void setCredentialSpread(Duration credentialSpread) {
        this.credentialSpread = requireNonNegative(credentialSpread, "credentialSpread");
    }

    /** @see #credentialMargin */
    public void setCredentialMargin(Duration credentialMargin) {
        this.credentialMargin = requireNonNegative(credentialMargin, "credentialMargin");
    }

    /** @see #credentialExpiry */
    public Supplier<Instant> getCredentialExpiry() {
        return credentialExpiry;
    }

    /** @see #credentialExpiry */
    public void setCredentialExpiry(Supplier<Instant> credentialExpiry) {
        this.credentialExpiry = credentialExpiry;
    }

    /**
     * How long {@code close()} waits for borrowed connections to come back
     * before it cuts them - see {@link SeclumePool#close(Duration)}. Ten
     * seconds by default, inside the thirty a container platform usually
     * gives a process between SIGTERM and SIGKILL; 0 cuts them at once.
     */
    public Duration getShutdownTimeout() {
        return shutdownTimeout;
    }

    public void setShutdownTimeout(Duration shutdownTimeout) {
        this.shutdownTimeout = requireNonNegative(shutdownTimeout, "shutdownTimeout");
    }

    /**
     * What every borrowed connection is to carry as session context - the
     * tenant of the current request, say - asked on each borrow; null or an
     * empty map for none. See {@link space.seclume.SessionContext}: the value
     * goes with the borrower's first statement where the protocol lets it,
     * and the pool's reset on return takes it off again.
     */
    public Supplier<java.util.Map<String, String>> getSessionContext() {
        return sessionContext;
    }

    public void setSessionContext(Supplier<java.util.Map<String, String>> sessionContext) {
        this.sessionContext = sessionContext;
    }

    /** How often an idle connection is nudged; 0 switches it off. */
    public Duration getKeepaliveTime() {
        return keepaliveTime;
    }

    public void setKeepaliveTime(Duration keepaliveTime) {
        this.keepaliveTime = requireNonNegative(keepaliveTime, "keepaliveTime");
    }

    /**
     * How long a returned connection is trusted without being probed again.
     *
     * <p>Checking every handout costs a <b>round trip to the server</b>, and
     * that is not a detail: measured against HikariCP it turned borrowing a
     * connection from a fraction of a microsecond into sixty. A connection
     * that came back a moment ago and has since been lying in this process is
     * as alive as the probe would find it - and if it is not, the first
     * statement says so and the pool retires it.
     *
     * <p>Zero means: probe every time. That is the slow, paranoid setting, and
     * it is available for whoever wants it.
     */
    public Duration getValidationBypassWindow() {
        return validationBypassWindow;
    }

    public void setValidationBypassWindow(Duration validationBypassWindow) {
        this.validationBypassWindow =
                requireNonNegative(validationBypassWindow, "validationBypassWindow");
    }

    public Duration getValidationTimeout() {
        return validationTimeout;
    }

    public void setValidationTimeout(Duration validationTimeout) {
        this.validationTimeout = requirePositive(validationTimeout, "validationTimeout");
    }

    /**
     * From when a borrowed connection counts as forgotten; 0 switches it off.
     *
     * <p>It is reported with the stack trace of the borrow - without that,
     * nobody knows which piece of code is not giving the connection back.
     */
    public Duration getLeakDetectionThreshold() {
        return leakDetectionThreshold;
    }

    public void setLeakDetectionThreshold(Duration leakDetectionThreshold) {
        this.leakDetectionThreshold =
                requireNonNegative(leakDetectionThreshold, "leakDetectionThreshold");
    }

    /**
     * Whether the pool opens {@link #getMinimumIdle()} connections at startup
     * already. For the first call after startup that is the difference between
     * microseconds and a complete handshake.
     */
    public boolean isWarmup() {
        return warmup;
    }

    /**
     * How many prepared statements a connection keeps between borrows.
     *
     * <p>Sixty-four by default, and it used to be zero. The old reasoning was
     * that no other pool caches statements either - which is true and beside
     * the point: <b>HikariCP does not cache because pgjdbc does</b>, with 256
     * queries per connection, switched on out of the box. Our driver has no
     * such cache of its own, so zero here meant no caching anywhere, while the
     * combination it was being compared against cached all along.
     *
     * <p>What that cost is measured. Borrow, prepare, execute, return - the
     * shape every framework uses, because Hibernate and Spring Data prepare
     * every statement:
     *
     * <pre>
     * HikariCP + pgjdbc          832 B    59.6 us
     * seclume, cache off       1235 B   111.1 us
     * seclume, cache on         464 B    58.0 us
     * </pre>
     *
     * <p>Off, the most common shape in production was twice as slow as
     * HikariCP; on, it allocates a little over half as much and is no slower.
     * A default that loses by a factor of two on the ordinary case is not a
     * safe default, it is a trap.
     *
     * <p>Zero still switches it off. What it costs: the server keeps a plan
     * per cached statement per connection, and a connection that sees more
     * than sixty-four distinct statements churns the cache rather than
     * growing it - bounded, because a cache without a bound is a leak with
     * good manners. A plan lives in a session, so the cache belongs to the
     * physical connection and goes when it does.
     */
    public void setStatementCacheSize(int statementCacheSize) {
        if (statementCacheSize < 0) {
            throw new IllegalArgumentException(
                    "the statement cache size cannot be negative: " + statementCacheSize);
        }
        this.statementCacheSize = statementCacheSize;
    }

    public int getStatementCacheSize() {
        return statementCacheSize;
    }

    /**
     * Whether a connection that breaks while it is borrowed is rebuilt quietly.
     *
     * <p>A connection that breaks <b>in the pool</b> never reaches anybody: it
     * is checked before it goes out. The one this is about breaks while an
     * application holds it - a rollout, a firewall that forgets the socket, a
     * server that goes away between two statements. Other pools can only hand
     * the failure on, because rebuilding needs the password and they would have
     * to keep it. seclume asks its secret source again, which is exactly what
     * it is for.
     *
     * <p>Quiet, but only where quiet is honest. It happens when all of this
     * holds: no transaction is open, no statement handed out is still open, no
     * savepoint stands, and the call that failed was one the connection itself
     * answers. Then the failed call is repeated once on the new connection and
     * the application sees nothing - which is the truth, because it would have
     * got another connection from the pool anyway. In every other case the
     * exception goes through untouched: repeating work whose outcome nobody can
     * establish is how a booking happens twice.
     *
     * <p>The session settings seclume knows about are set again on the new
     * connection: autocommit, read-only, isolation level, catalog and schema.
     * What the application sent past the pool as SQL - a temporary table, a
     * session variable - is gone, and that is why this stays switchable.
     */
    public void setRenewBrokenConnections(boolean renewBrokenConnections) {
        this.renewBrokenConnections = renewBrokenConnections;
    }

    public boolean isRenewBrokenConnections() {
        return renewBrokenConnections;
    }

    public void setWarmup(boolean warmup) {
        this.warmup = warmup;
    }

    private static Duration requirePositive(Duration value, String what) {
        if (value == null || value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(what + " must be greater than zero");
        }
        return value;
    }

    private static Duration requireNonNegative(Duration value, String what) {
        if (value == null || value.isNegative()) {
            throw new IllegalArgumentException(what + " must not be negative");
        }
        return value;
    }

    /** Numbers only - there is nothing here that could be a secret. */
    @Override
    public String toString() {
        return "PoolSettings[name=" + name
                + ", maximumPoolSize=" + maximumPoolSize
                + ", minimumIdle=" + getMinimumIdle()
                + ", connectionTimeout=" + connectionTimeout
                + ", idleTimeout=" + idleTimeout
                + ", maxLifetime=" + maxLifetime
                + ", credentialMargin=" + credentialMargin
                + ", credentialSpread=" + credentialSpread
                + ", keepaliveTime=" + keepaliveTime
                + ", shutdownTimeout=" + shutdownTimeout
                + ", leakDetectionThreshold=" + leakDetectionThreshold
                + ", warmup=" + warmup + "]";
    }
}
