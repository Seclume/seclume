package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.jdbc.autoconfigure.JdbcConnectionDetails;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import space.seclume.pool.SeclumePool;
import space.seclume.tck.TestHosts;

/**
 * What Testcontainers' {@code @ServiceConnection} and Docker Compose support
 * hand over - a {@link JdbcConnectionDetails} with the container's vendor URL,
 * user and password - becomes a seclume pool.
 */
class ConnectionDetailsTest {

    @Test
    void theUrlsTheContainersUseAreTranslated() {
        assertEquals("jdbc:seclume:postgresql://localhost:32768/test",
                SeclumeConnectionDetailsAutoConfiguration.translate(
                        "jdbc:postgresql://localhost:32768/test?loggerLevel=OFF"));
        assertEquals("jdbc:seclume:mysql://localhost:32769/test?allowPublicKeyRetrieval=true",
                SeclumeConnectionDetailsAutoConfiguration.translate(
                        "jdbc:mysql://localhost:32769/test?useSSL=false"));
        assertEquals("jdbc:seclume:mysql://localhost:32770/test?allowPublicKeyRetrieval=true",
                SeclumeConnectionDetailsAutoConfiguration.translate(
                        "jdbc:mariadb://localhost:32770/test"));
        assertEquals("jdbc:seclume:sqlserver://localhost:32771/master?trustServerCertificate=true",
                SeclumeConnectionDetailsAutoConfiguration.translate(
                        "jdbc:sqlserver://localhost:32771;encrypt=false"));
        assertEquals("jdbc:seclume:oracle://localhost:32772/freepdb1",
                SeclumeConnectionDetailsAutoConfiguration.translate(
                        "jdbc:oracle:thin:@localhost:32772/freepdb1"));
    }

    @Test
    void aContainersConnectionDetailsBecomeTheApplicationsPool() throws Exception {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.register(Container.class, SeclumeAutoConfiguration.class,
                    SeclumeConnectionDetailsAutoConfiguration.class);
            context.refresh();
            DataSource dataSource = context.getBean(DataSource.class);
            assertTrue(dataSource instanceof SeclumePool, dataSource.getClass().getName());
            try (Connection connection = dataSource.getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select current_user")) {
                rows.next();
                assertEquals("seclume_test", rows.getString(1));
            }
        }
    }

    /** Stands in for a PostgreSQLContainer with @ServiceConnection. */
    @Configuration
    static class Container {

        @Bean
        JdbcConnectionDetails postgres() throws IOException {
            Path password = null;
            for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                    Path.of("..", TestHosts.postgresPasswordFile()))) {
                if (Files.isReadable(candidate)) {
                    password = candidate;
                }
            }
            Assumptions.assumeTrue(password != null, "no " + TestHosts.postgresPasswordFile());
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()),
                        2000);
            } catch (IOException e) {
                Assumptions.abort("no PostgreSQL on " + TestHosts.postgres());
            }
            // As Testcontainers reports it: a String. The test never prints it.
            String secret = Files.readString(password, StandardCharsets.UTF_8).strip(); // seclume-allow: a test database's password, handed over the way a container does
            String url = "jdbc:postgresql://" + TestHosts.postgres() + ":"
                    + TestHosts.postgresPort() + "/seclume_test?loggerLevel=OFF";
            return new JdbcConnectionDetails() {
                @Override
                public String getUsername() {
                    return "seclume_test";
                }

                @Override
                public String getPassword() {
                    return secret;
                }

                @Override
                public String getJdbcUrl() {
                    return url;
                }
            };
        }
    }
}
