package space.seclume.bench;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;

import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * The database under measurement, and both ways to reach it.
 *
 * <p>Every benchmark runs the same statement twice: once through seclume and
 * once through the vendor driver. Both get the same host, the same user and
 * the same password file, and both are used the way an application uses them.
 * A comparison in which one side is tuned and the other is not measures the
 * tuning, not the driver.
 *
 * <p>Configured entirely from system properties, so that one build can measure
 * against any of the four:
 *
 * <pre>
 * -Dbench.db=postgresql -Dbench.host=127.0.0.1 -Dbench.port=5432
 * -Dbench.database=seclume_test -Dbench.user=seclume_test
 * -Dbench.password.file=.local-pg-password
 * </pre>
 *
 * <p><b>The password is a {@code String} on the vendor side.</b> That is not
 * an oversight - it is the point being measured against: the other driver has
 * no way of taking it otherwise.
 */
public final class BenchDatabase {

    /** Which database this run measures against. */
    public enum Kind {
        POSTGRESQL, MYSQL, SQLSERVER, ORACLE
    }

    private final Kind kind;
    private final String host;
    private final int port;
    private final String database;
    private final String user;
    private final Path passwordFile;

    private BenchDatabase(Kind kind, String host, int port, String database, String user,
                          Path passwordFile) {
        this.kind = kind;
        this.host = host;
        this.port = port;
        this.database = database;
        this.user = user;
        this.passwordFile = passwordFile;
    }

    /** Reads the configuration, and says what is missing rather than guessing. */
    public static BenchDatabase fromSystemProperties() {
        Kind kind = Kind.valueOf(property("bench.db", "postgresql").toUpperCase(
                java.util.Locale.ROOT));
        int defaultPort = switch (kind) {
            case POSTGRESQL -> 5432;
            case MYSQL -> 3306;
            case SQLSERVER -> 1433;
            case ORACLE -> 1521;
        };
        Path passwordFile = Path.of(property("bench.password.file", ".local-pg-password"));
        if (!Files.exists(passwordFile)) {
            throw new IllegalStateException("no password file at "
                    + passwordFile.toAbsolutePath() + " - set -Dbench.password.file");
        }
        return new BenchDatabase(kind,
                property("bench.host", "127.0.0.1"),
                Integer.parseInt(property("bench.port", Integer.toString(defaultPort))),
                property("bench.database", kind == Kind.ORACLE ? "FREEPDB1" : "seclume_test"),
                property("bench.user", "seclume_test"),
                passwordFile);
    }

    private static String property(String key, String fallback) {
        String value = System.getProperty(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    public Kind kind() {
        return kind;
    }

    /** {@code select 1} - spelled the way this server spells it. */
    public String selectOne() {
        return kind == Kind.ORACLE ? "select 1 from dual" : "select 1";
    }

    /** A statement that produces {@code rows} rows of three columns. */
    public String selectRows(int rows) {
        return switch (kind) {
            case POSTGRESQL -> "select i, 'text-' || i, i * 1.5 from generate_series(1, "
                    + rows + ") i";
            case ORACLE -> "select level, 'text-' || level, level * 1.5 from dual "
                    + "connect by level <= " + rows;
            case SQLSERVER -> "with numbers as (select 1 as i union all select i + 1 from "
                    + "numbers where i < " + rows + ") select i, concat('text-', i), "
                    + "i * 1.5 from numbers option (maxrecursion 0)";
            case MYSQL -> "with recursive numbers as (select 1 as i union all select i + 1 "
                    + "from numbers where i < " + rows + ") select i, concat('text-', i), "
                    + "i * 1.5 from numbers";
        };
    }

    /** The one-row statement with a bind variable, in this dialect's spelling. */
    public String selectWithParameter() {
        return switch (kind) {
            case ORACLE -> "select 1, 'text', 1.5 from dual where 1 = ?";
            case SQLSERVER, POSTGRESQL, MYSQL -> "select 1, 'text', 1.5 where 1 = ?";
        };
    }

    /** The table the insert benchmark writes into, in this dialect. */
    public String createInsertTable() {
        return switch (kind) {
            case POSTGRESQL -> "create table zl_bench_insert (n integer, t varchar(40))";
            case MYSQL -> "create table zl_bench_insert (n int, t varchar(40))";
            case SQLSERVER -> "create table zl_bench_insert (n int, t varchar(40))";
            case ORACLE -> "create table zl_bench_insert (n number(9), t varchar2(40))";
        };
    }

    /** The seclume {@code DataSource} for this database. */
    public DataSource seclume() throws SQLException {
        SecretProvider secret = new FileSecretProvider(passwordFile.toAbsolutePath(), 256);
        return switch (kind) {
            case POSTGRESQL -> {
                var source = new space.seclume.postgresql.jdbc.SeclumeDataSource();
                source.setHost(host);
                source.setPort(port);
                source.setDatabase(database);
                source.setUser(user);
                source.setSecretProvider(secret);
                yield source;
            }
            case MYSQL -> {
                var source = new space.seclume.mysql.jdbc.MyDataSource();
                source.setHost(host);
                source.setPort(port);
                source.setDatabase(database);
                source.setUser(user);
                source.setSecretProvider(secret);
                // The same setting the vendor URL carries, so that both sides
                // do the same thing: without TLS, MySQL 8 needs the server's
                // public key, and asking an unauthenticated server for one is
                // off by default in this driver.
                source.setAllowPublicKeyRetrieval(true);
                yield source;
            }
            case SQLSERVER -> {
                var source = new space.seclume.sqlserver.jdbc.TdsDataSource();
                source.setHost(host);
                source.setPort(port);
                source.setDatabase(database);
                source.setUser(user);
                source.setSecretProvider(secret);
                source.setTrustServerCertificate(true);
                yield source;
            }
            case ORACLE -> {
                var source = new space.seclume.oracle.jdbc.OraDataSource();
                source.setHost(host);
                source.setPort(port);
                source.setService(database);
                source.setUser(user);
                source.setSecretProvider(secret);
                yield source;
            }
        };
    }

    /** The vendor driver's URL for the same server. */
    public String vendorUrl() {
        return switch (kind) {
            case POSTGRESQL -> "jdbc:postgresql://" + host + ":" + port + "/" + database;
            case MYSQL -> "jdbc:mysql://" + host + ":" + port + "/" + database
                    + "?allowPublicKeyRetrieval=true&useSSL=false";
            case SQLSERVER -> "jdbc:sqlserver://" + host + ":" + port
                    + ";databaseName=" + database + ";encrypt=true;trustServerCertificate=true";
            case ORACLE -> "jdbc:oracle:thin:@//" + host + ":" + port + "/" + database;
        };
    }

    public String user() {
        return user;
    }

    /**
     * The password as the vendor driver needs it - as a {@code String}.
     *
     * <p>Which is the whole comparison in one line: on this side it lands on
     * the heap and stays there, and no configuration of that driver changes
     * it.
     */
    public String vendorPassword() throws SQLException {
        try {
            // seclume-allow: the vendor drivers take the password as a String and there is no other way in - that is the very thing being compared here, and it is the measuring harness, not the library
            byte[] bytes = Files.readAllBytes(passwordFile);
            int end = bytes.length;
            while (end > 0 && (bytes[end - 1] == '\n' || bytes[end - 1] == '\r')) {
                end--;
            }
            // seclume-allow: see above - this String is what the vendor driver demands
            return new String(bytes, 0, end, java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new SQLException("cannot read " + passwordFile, e);
        }
    }

    /** Properties for the vendor driver, user and password included. */
    public Properties vendorProperties() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", user);
        properties.setProperty("password", vendorPassword());
        // Whatever else a particular run needs on the vendor side, named in
        // one place so that a measurement says in its command line what it
        // changed about the other driver:
        //   -Dbench.vendor.properties=binaryTransfer=false,loggerLevel=OFF
        // Nothing is set here by default, because a comparison in which one
        // side is configured and the other is not measures the configuration.
        String extra = System.getProperty("bench.vendor.properties", "");
        for (String pair : extra.split(",")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                properties.setProperty(pair.substring(0, equals).trim(),
                        pair.substring(equals + 1).trim());
            }
        }
        return properties;
    }

    @Override
    public String toString() {
        return kind + " " + host + ":" + port + "/" + database + " as " + user;
    }
}
