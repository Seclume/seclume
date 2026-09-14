package space.seclume.spring;

import javax.sql.DataSource;

import org.springframework.beans.factory.BeanFactory;

import space.seclume.internal.JdbcUrl;
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
        String url = properties.getUrl();
        if (url == null || url.isBlank()) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".url is missing");
        }
        SecretProvider secret = new SecretProviderFactory(beans)
                .create(name, properties.getSecret());
        if (secret == null) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".secret.provider is 'integrated', but "
                    + "integrated authentication (Kerberos/SSPI) is not implemented yet - "
                    + "it belongs to the SQL Server driver, which is still open");
        }
        String user = properties.getUsername();
        if (user == null || user.isBlank()) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".username is missing - seclume does not "
                    + "guess the database user");
        }

        if (url.startsWith("jdbc:seclume:postgresql:")) {
            return requireDriver(name, url, "space.seclume.postgresql.jdbc.SeclumeDataSource",
                    "seclume-postgresql")
                    ? Postgres.create(url, user, secret) : null;
        }
        if (url.startsWith("jdbc:seclume:mysql:") || url.startsWith("jdbc:seclume:mariadb:")) {
            return requireDriver(name, url, "space.seclume.mysql.jdbc.MyDataSource",
                    "seclume-mysql")
                    ? MySql.create(url, user, secret) : null;
        }
        if (url.startsWith("jdbc:seclume:sqlserver:") || url.startsWith("jdbc:seclume:mssql:")) {
            return requireDriver(name, url, "space.seclume.sqlserver.jdbc.TdsDataSource",
                    "seclume-sqlserver")
                    ? SqlServer.create(url, user, secret) : null;
        }
        if (url.startsWith("jdbc:seclume:oracle:")) {
            return requireDriver(name, url, "space.seclume.oracle.jdbc.OraDataSource",
                    "seclume-oracle")
                    ? Oracle.create(url, user, secret) : null;
        }
        throw new IllegalStateException(
                "seclume.datasources." + name + ".url is '" + url + "', which no seclume "
                + "driver handles. Known prefixes: jdbc:seclume:postgresql:, "
                + "jdbc:seclume:mysql:, jdbc:seclume:mariadb:, jdbc:seclume:sqlserver:, "
                + "jdbc:seclume:oracle:");
    }

    /** Says which module is missing instead of throwing a {@code NoClassDefFoundError}. */
    private static boolean requireDriver(String name, String url, String className,
                                         String artifact) {
        try {
            Class.forName(className, false, SeclumeDataSources.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + " uses " + url + ", but the driver is not "
                    + "on the classpath - add the dependency " + artifact, e);
        }
    }

    /** Loaded only once the URL points at PostgreSQL. */
    private static final class Postgres {

        static DataSource create(String url, String user, SecretProvider secret) {
            JdbcUrl.Parsed parsed = JdbcUrl.parse(url, null, "jdbc:seclume:postgresql:", 5432);
            var source = new space.seclume.postgresql.jdbc.SeclumeDataSource();
            source.setHost(parsed.host());
            source.setPort(parsed.port());
            // Several servers in the URL mean failover at connect time; with
            // one host this is exactly what setHost/setPort already said.
            source.setHosts(parsed.hosts().text());
            source.setDatabase(parsed.database());
            source.setUser(user);
            source.setSecretProvider(secret);
            source.setApplicationName(parsed.option("applicationName", "seclume"));
            source.setConnectTimeoutMillis(parsed.number("connectTimeout", 10_000));
            return source;
        }
    }

    /** Loaded only once the URL points at SQL Server. */
    private static final class SqlServer {

        static DataSource create(String url, String user, SecretProvider secret) {
            String prefix = url.startsWith("jdbc:seclume:mssql:")
                    ? "jdbc:seclume:mssql:" : "jdbc:seclume:sqlserver:";
            JdbcUrl.Parsed parsed = JdbcUrl.parse(url, null, prefix, 1433);
            var source = new space.seclume.sqlserver.jdbc.TdsDataSource();
            source.setHost(parsed.host());
            source.setPort(parsed.port());
            // Several servers in the URL mean failover at connect time; with
            // one host this is exactly what setHost/setPort already said.
            source.setHosts(parsed.hosts().text());
            source.setDatabase(parsed.database());
            source.setUser(user);
            source.setSecretProvider(secret);
            source.setApplicationName(parsed.option("applicationName", "seclume"));
            source.setConnectTimeoutMillis(parsed.number("connectTimeout", 10_000));
            source.setTrustServerCertificate(parsed.flag("trustServerCertificate", false));
            return source;
        }
    }

    /**
     * Loaded only once the URL points at Oracle.
     *
     * <p>Oracle names a <b>service</b> where the others name a database, and
     * the URL carries it in the same place - so the parsed database is the
     * service here.
     */
    private static final class Oracle {

        static DataSource create(String url, String user, SecretProvider secret) {
            JdbcUrl.Parsed parsed = JdbcUrl.parse(url, null, "jdbc:seclume:oracle:", 1521);
            var source = new space.seclume.oracle.jdbc.OraDataSource();
            source.setHost(parsed.host());
            source.setPort(parsed.port());
            // Several servers in the URL mean failover at connect time; with
            // one host this is exactly what setHost/setPort already said.
            source.setHosts(parsed.hosts().text());
            source.setService(parsed.database());
            source.setUser(user);
            source.setSecretProvider(secret);
            source.setConnectTimeoutMillis(parsed.number("connectTimeout", 10_000));
            return source;
        }
    }

    /** Loaded only once the URL points at MySQL or MariaDB. */
    private static final class MySql {

        static DataSource create(String url, String user, SecretProvider secret) {
            String prefix = url.startsWith("jdbc:seclume:mariadb:")
                    ? "jdbc:seclume:mariadb:" : "jdbc:seclume:mysql:";
            JdbcUrl.Parsed parsed = JdbcUrl.parse(url, null, prefix, 3306);
            var source = new space.seclume.mysql.jdbc.MyDataSource();
            source.setHost(parsed.host());
            source.setPort(parsed.port());
            // Several servers in the URL mean failover at connect time; with
            // one host this is exactly what setHost/setPort already said.
            source.setHosts(parsed.hosts().text());
            source.setDatabase(parsed.database());
            source.setUser(user);
            source.setSecretProvider(secret);
            source.setApplicationName(parsed.option("applicationName", "seclume"));
            source.setConnectTimeoutMillis(parsed.number("connectTimeout", 10_000));
            source.setAllowPublicKeyRetrieval(parsed.flag("allowPublicKeyRetrieval", false));
            return source;
        }
    }
}
