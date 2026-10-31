package space.seclume.micronaut;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.micronaut.context.ApplicationContext;

import space.seclume.pool.SeclumePool;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * A Micronaut application against CI's PostgreSQL, configured by properties
 * alone: the pool logs in through the provider the URL names - and afterwards
 * a heap dump of the process holds no byte of the password.
 */
class LocalMicronautPostgresTest {

    @Test
    void aMicronautApplicationLogsInAndThePasswordIsNotOnTheHeap() throws Exception {
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
        try (ApplicationContext context = ApplicationContext.run(Map.of(
                "seclume.datasources.default.url", url,
                "seclume.datasources.default.pool.maximum-pool-size", "2",
                "seclume.datasources.default.pool.warmup", "true"))) {
            SeclumePool pool = context.getBean(SeclumePool.class);
            try (Connection connection = pool.getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select current_user")) {
                rows.next();
                assertEquals("seclume_test", rows.getString(1));
            }
            NoSecretInHeap.assertAbsent(password);
        }
    }
}
