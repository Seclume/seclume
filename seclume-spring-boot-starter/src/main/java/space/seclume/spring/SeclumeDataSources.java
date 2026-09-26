package space.seclume.spring;

import javax.sql.DataSource;

import org.springframework.beans.factory.BeanFactory;

import space.seclume.secret.SecretProvider;

/**
 * Turns URL, user and secret source into the {@code DataSource} of the
 * matching driver.
 *
 * <p>The drivers are optional dependencies - whoever uses only PostgreSQL
 * should not have to drag the other three along. Each driver therefore lives
 * in an inner class of its own: that is loaded only once the URL really points
 * at this driver. Were they named in one method, the JVM would load all of
 * them on the first call and, without the others, abort with a
 * {@code NoClassDefFoundError}.
 */
final class SeclumeDataSources {

    private SeclumeDataSources() {
    }

    static DataSource create(String name, SeclumeProperties.DataSourceProperties properties,
                             BeanFactory beans) {
        String configured = properties.getUrl();
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".url is missing");
        }
        String url = withResultLimit(name, configured, Runtime.getRuntime().maxMemory());
        SecretProvider secret = new SecretProviderFactory(beans)
                .create(name, properties.getSecret());
        if (secret == null) {
            // 'integrated': Kerberos, with the operating system's ticket and no
            // secret here at all - which PostgreSQL and MariaDB on Linux speak
            // (GSSAPI).
            if (url.startsWith("jdbc:seclume:postgresql:") || url.startsWith("jdbc:seclume:mariadb:")
                    || url.startsWith("jdbc:seclume:mysql:")) {
                secret = space.seclume.secret.SecretProviders.of(java.util.Map.of("provider", "none"));
            } else {
                throw new IllegalStateException(
                        "seclume.datasources." + name + ".secret.provider is 'integrated': "
                        + "Kerberos works for PostgreSQL and MariaDB on Linux (GSSAPI); for "
                        + "this database (SQL Server Integrated Security, Oracle) and for "
                        + "Windows (SSPI) it is not implemented yet");
            }
        }
        String user = properties.getUsername();
        if (user == null || user.isBlank()) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".username is missing - seclume does not "
                    + "guess the database user");
        }
        return forUrl(name, url, user, secret);
    }

    /** The driver's DataSource for a {@code jdbc:seclume:} URL - by its prefix. */
    static DataSource forUrl(String name, String url, String user, SecretProvider secret) {
        if (url.startsWith("jdbc:seclume:postgresql:")) {
            return requireDriver(name, url, "space.seclume.postgresql.jdbc.SeclumeDataSource",
                    "seclume-postgresql")
                    ? built(name, url, () -> Postgres.create(url, user, secret)) : null;
        }
        if (url.startsWith("jdbc:seclume:mysql:") || url.startsWith("jdbc:seclume:mariadb:")) {
            return requireDriver(name, url, "space.seclume.mysql.jdbc.MyDataSource",
                    "seclume-mysql")
                    ? built(name, url, () -> MySql.create(url, user, secret)) : null;
        }
        if (url.startsWith("jdbc:seclume:sqlserver:") || url.startsWith("jdbc:seclume:mssql:")) {
            return requireDriver(name, url, "space.seclume.sqlserver.jdbc.TdsDataSource",
                    "seclume-sqlserver")
                    ? built(name, url, () -> SqlServer.create(url, user, secret)) : null;
        }
        if (url.startsWith("jdbc:seclume:oracle:")) {
            return requireDriver(name, url, "space.seclume.oracle.jdbc.OraDataSource",
                    "seclume-oracle")
                    ? built(name, url, () -> Oracle.create(url, user, secret)) : null;
        }
        throw new IllegalStateException(
                "seclume.datasources." + name + ".url is '" + space.seclume.internal.JdbcUrl.redact(url) + "', which no seclume "
                + "driver handles. Known prefixes: jdbc:seclume:postgresql:, "
                + "jdbc:seclume:mysql:, jdbc:seclume:mariadb:, jdbc:seclume:sqlserver:, "
                + "jdbc:seclume:oracle:");
    }

    /** Building one reads the URL, and a URL can be refused. */
    @FunctionalInterface
    private interface Build {
        DataSource build() throws java.sql.SQLException;
    }

    private static final System.Logger LOG = System.getLogger(SeclumeDataSources.class.getName());

    /**
     * A URL that sets no limit on a result gets one: a quarter of the heap,
     * between 16 and 256 MB.
     *
     * <p>Without a limit a runaway query - a missing {@code where}, a join
     * that multiplies - reads rows until the heap is gone, and the
     * OutOfMemoryError takes the whole application with it, every other
     * request included. With one, that statement fails with an exception that
     * names the limit and the statement, and nothing else notices. A result
     * the application really wants bigger is one URL option away
     * ({@code maxResultBytes}, {@code maxResultRows}); {@code maxResultBytes=0}
     * switches the limit off, and says so by being written down.
     */
    static String withResultLimit(String name, String url, long maxHeap) {
        if (url.contains("maxResultBytes=") || url.contains("maxResultRows=")) {
            return url;
        }
        long limit = Math.max(16L << 20, Math.min(256L << 20, maxHeap / 4));
        LOG.log(System.Logger.Level.INFO, "seclume.datasources." + name + ": results are "
                + "limited to " + (limit >> 20) + " MB (a quarter of the heap) - set "
                + "maxResultBytes in the URL for another limit, maxResultBytes=0 for none");
        int hash = url.indexOf('#');
        String head = hash < 0 ? url : url.substring(0, hash);
        String tail = hash < 0 ? "" : url.substring(hash);
        return head + (head.contains("?") ? "&" : "?") + "maxResultBytes=" + limit + tail;
    }

    private static DataSource built(String name, String url, Build build) {
        try {
            return build.build();
        } catch (java.sql.SQLException refused) {
            throw new IllegalStateException("seclume.datasources." + name + ".url '"
                    + space.seclume.internal.JdbcUrl.redact(url) + "' was refused: "
                    + refused.getMessage(), refused);
        }
    }

    /** Says which module is missing instead of throwing a {@code NoClassDefFoundError}. */
    private static boolean requireDriver(String name, String url, String className,
                                         String artifact) {
        try {
            Class.forName(className, false, SeclumeDataSources.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + " uses " + space.seclume.internal.JdbcUrl.redact(url) + ", but the driver is not "
                    + "on the classpath - add the dependency " + artifact, e);
        }
    }

    /**
     * The URL as the driver reads it, with the user and the secret beside it.
     *
     * <p>This used to copy the URL into the {@code DataSource} one setter at a
     * time - host, port, database, a timeout and a flag or two - and whatever
     * was not on that list did not arrive. {@code tls=verify-full} was not on
     * it: a Spring application that asked for a checked certificate got
     * {@code prefer} on PostgreSQL and MySQL and no TLS at all on Oracle, and
     * nothing said so. The client certificate, {@code targetServerType}, the
     * result limits and the rest went the same way. Handing over the whole URL
     * is the only version of this that cannot fall behind the driver.
     *
     * <p>{@code provider=none} stands in for the secret while the URL is
     * read, because the provider comes from {@code secret.*} rather than from
     * the URL; the real one is set straight after and replaces it.
     */
    private static java.util.Properties beside(String user) {
        java.util.Properties properties = new java.util.Properties();
        properties.setProperty("user", user);
        properties.setProperty("provider", "none");
        return properties;
    }

    /** Loaded only once the URL points at PostgreSQL. */
    private static final class Postgres {

        static DataSource create(String url, String user, SecretProvider secret)
                throws java.sql.SQLException {
            var source = new space.seclume.postgresql.jdbc.SeclumeDataSource();
            source.setUrl(url, beside(user));
            source.setUser(user);
            source.setSecretProvider(secret);
            return source;
        }
    }

    /** Loaded only once the URL points at SQL Server. */
    private static final class SqlServer {

        static DataSource create(String url, String user, SecretProvider secret)
                throws java.sql.SQLException {
            var source = new space.seclume.sqlserver.jdbc.TdsDataSource();
            source.setUrl(url, beside(user));
            source.setUser(user);
            source.setSecretProvider(secret);
            return source;
        }
    }

    /**
     * Loaded only once the URL points at Oracle.
     *
     * <p>Oracle names a <b>service</b> where the others name a database, and
     * the URL carries it in the same place.
     */
    private static final class Oracle {

        static DataSource create(String url, String user, SecretProvider secret)
                throws java.sql.SQLException {
            var source = new space.seclume.oracle.jdbc.OraDataSource();
            source.setUrl(url, beside(user));
            source.setUser(user);
            source.setSecretProvider(secret);
            return source;
        }
    }

    /** Loaded only once the URL points at MySQL or MariaDB. */
    private static final class MySql {

        static DataSource create(String url, String user, SecretProvider secret)
                throws java.sql.SQLException {
            var source = new space.seclume.mysql.jdbc.MyDataSource();
            source.setUrl(url, beside(user));
            source.setUser(user);
            source.setSecretProvider(secret);
            return source;
        }
    }
}
