package space.seclume.micronaut;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import io.micronaut.context.ApplicationContext;
import io.micronaut.transaction.TransactionOperations;

import space.seclume.pool.SeclumePool;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Micronaut Data JDBC on seclume's pool, against CI's PostgreSQL: a
 * repository Micronaut wrote at compile time saves, finds, counts and
 * deletes through the {@code DataSource} that {@code seclume.datasources.default}
 * made; a transaction through Micronaut's transaction manager commits or
 * rolls back on the pool's connection; and afterwards a heap dump holds no
 * byte of the password. Nothing in the repository or the configuration knows
 * about seclume beyond the URL.
 *
 * <p>Isolated: the field encryption ring and the heap dump are the JVM's.
 */
@Isolated
class LocalMicronautDataPostgresTest {

    private static Path passwordFile() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    @Test
    void aMicronautDataRepositoryWorksOnThePool() throws Exception {
        Path password = passwordFile();
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
                "seclume.datasources.default.pool.maximum-pool-size", "3"))) {
            SeclumePool pool = context.getBean(SeclumePool.class);
            try (Connection connection = pool.getConnection(); Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists zl_mn_patient");
                statement.execute("create table zl_mn_patient (id bigint primary key, name text, ward text)");
            }
            try {
                DataPatients patients = context.getBean(DataPatients.class);
                patients.saveAll(List.of(new DataPatient(1L, "Ada", "north"), new DataPatient(2L, "Brigitte", "south"),
                        new DataPatient(3L, "Chen", "north")));
                assertEquals(3, patients.count());
                assertEquals("Brigitte", patients.findById(2L).orElseThrow().name());
                assertEquals(List.of(1L, 3L), patients.findByWardOrderById("north").stream()
                        .map(DataPatient::id).toList(), "a query Micronaut derived from the method's name");
                assertEquals(2, patients.countByWard("north"));
                patients.update(new DataPatient(3L, "Chen Wei", "south"));
                assertEquals("Chen Wei", patients.findById(3L).orElseThrow().name());

                @SuppressWarnings("unchecked")
                TransactionOperations<Connection> transactions = context.getBean(TransactionOperations.class);
                transactions.executeWrite(status -> {
                    patients.save(new DataPatient(4L, "Dara", "east"));
                    status.setRollbackOnly();
                    return null;
                });
                assertTrue(patients.findById(4L).isEmpty(), "rolled back on the pool's connection");
                transactions.executeWrite(status -> patients.save(new DataPatient(5L, "Emil", "east")));
                assertTrue(patients.findById(5L).isPresent(), "committed");
                assertThrows(RuntimeException.class, () -> transactions.executeWrite(status -> {
                    patients.save(new DataPatient(6L, "Femi", "east"));
                    throw new IllegalStateException("the work failed");
                }));
                assertTrue(patients.findById(6L).isEmpty(), "an exception rolls back");

                patients.deleteById(1L);
                assertEquals(3, patients.count());
                NoSecretInHeap.assertAbsent(password);
            } finally {
                try (Connection connection = pool.getConnection(); Statement statement = connection.createStatement()) {
                    statement.execute("drop table if exists zl_mn_patient");
                }
            }
        }
    }
}
