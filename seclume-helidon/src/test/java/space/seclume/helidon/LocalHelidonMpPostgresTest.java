package space.seclume.helidon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import jakarta.enterprise.inject.literal.NamedLiteral;
import jakarta.enterprise.inject.se.SeContainer;
import jakarta.enterprise.inject.se.SeContainerInitializer;

import org.eclipse.microprofile.config.spi.ConfigProviderResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * A Helidon MP application against CI's PostgreSQL: the CDI extension makes
 * the pool a {@code DataSource} bean from MicroProfile Config alone, the
 * injected bean logs in through the provider the URL names, two named pools
 * stay apart, and afterwards a heap dump of the process holds no byte of the
 * password.
 *
 * <p>Isolated: the container, the system properties and the heap dump are
 * the JVM's.
 */
@Isolated
class LocalHelidonMpPostgresTest {

    @Test
    void anInjectedDataSourceLogsInAndThePasswordIsNotOnTheHeap() throws Exception {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no PostgreSQL on " + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        }
        String url = "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":" + TestHosts.postgresPort()
                + "/seclume_test?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace('\\', '/');
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("mp.initializer.allow", "true");
        settings.put("mp.initializer.no-warn", "true");
        settings.put("seclume.datasources.default.url", url);
        settings.put("seclume.datasources.default.pool.maximum-pool-size", "2");
        settings.put("seclume.datasources.reports.url", url + "&applicationName=zl-reports");
        settings.put("seclume.datasources.reports.pool.maximum-pool-size", "1");
        settings.forEach(System::setProperty);
        ConfigProviderResolver resolver = ConfigProviderResolver.instance();
        resolver.releaseConfig(resolver.getConfig(Thread.currentThread().getContextClassLoader()));
        try (SeContainer container = SeContainerInitializer.newInstance().initialize()) {
            DataSource primary = container.select(DataSource.class).get();
            assertEquals("seclume_test", query(primary, "select current_user"));
            DataSource reports = container.select(DataSource.class, NamedLiteral.of("reports")).get();
            assertSame(reports, container.select(DataSource.class, SeclumeDataSource.Literal.of("reports")).get());
            assertEquals("zl-reports", query(reports, "select current_setting('application_name')"),
                    "the named pool is its own, with its own URL");
            NoSecretInHeap.assertAbsent(password);
        } finally {
            settings.keySet().forEach(System::clearProperty);
            resolver.releaseConfig(resolver.getConfig(Thread.currentThread().getContextClassLoader()));
        }
    }

    private static String query(DataSource source, String sql) throws Exception {
        try (Connection connection = source.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
