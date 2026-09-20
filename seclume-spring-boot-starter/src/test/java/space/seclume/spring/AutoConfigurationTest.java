package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import space.seclume.tck.TestHosts;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;

import space.seclume.pool.SeclumePool;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * The goal, checked against a real database: add the dependency,
 * fill in the configuration, done.
 *
 * <p>In none of these tests is there a {@code @Bean} method for a
 * {@code DataSource} or a call into a driver - only properties. That is exactly
 * the promise.
 *
 * <p>The context is built by hand rather than with the
 * {@code ApplicationContextRunner}: that one drags AssertJ along, and this
 * library otherwise gets by with the JDK and Spring.
 */
class AutoConfigurationTest {

    /** Where the live PostgreSQL is - see TestHosts, never a literal here. */
    private static final String POSTGRES_URL = "jdbc:seclume:postgresql://"
            + TestHosts.postgres() + ":" + TestHosts.postgresPort() + "/seclume_test";

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, TestHosts.postgresPasswordFile() + " is not there");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()), 1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on "
                    + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        }
    }

    /** Builds the context the way Spring Boot would with this configuration. */
    private static AnnotationConfigApplicationContext context(Map<String, Object> properties,
                                                              Class<?>... extra) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeAutoConfiguration.class);
        if (extra.length > 0) {
            context.register(extra);
        }
        context.refresh();
        return context;
    }

    private static Map<String, Object> postgres(String prefix) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put(prefix + ".url", POSTGRES_URL);
        properties.put(prefix + ".username", "seclume_test");
        properties.put(prefix + ".secret.provider", "file");
        properties.put(prefix + ".secret.path", passwordFile.toString().replace('\\', '/'));
        return properties;
    }

    @Test
    void oneDataSourceOutOfTheBox() throws Exception {
        try (AnnotationConfigApplicationContext context =
                     context(postgres("seclume.datasources.main"))) {
            DataSource dataSource = context.getBean(DataSource.class);
            assertTrue(dataSource instanceof SeclumePool, dataSource.getClass().getName());

            try (Connection connection = dataSource.getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("select current_user")) {
                assertTrue(result.next());
                assertEquals("seclume_test", result.getString(1));
            }
        }
    }

    @Test
    void poolSettingsComeFromTheConfiguration() {
        Map<String, Object> properties = postgres("seclume.datasources.main");
        properties.put("seclume.datasources.main.pool.maximum-pool-size", "3");
        properties.put("seclume.datasources.main.pool.minimum-idle", "1");
        properties.put("seclume.datasources.main.pool.connection-timeout", "2s");
        properties.put("seclume.datasources.main.pool.warmup", "true");

        try (AnnotationConfigApplicationContext context = context(properties)) {
            SeclumePool pool = context.getBean(SeclumePool.class);
            assertEquals(3, pool.settings().getMaximumPoolSize());
            assertEquals(1, pool.settings().getMinimumIdle());
            assertEquals(Duration.ofSeconds(2), pool.settings().getConnectionTimeout());
            assertEquals("seclume-main", pool.settings().getName());
            // warmup=true means the connection is already standing.
            assertEquals(1, pool.idleCount());
        }
    }

    @Test
    void severalDataSourcesGetTheirOwnBeans() {
        Map<String, Object> properties = postgres("seclume.datasources.main");
        properties.putAll(postgres("seclume.datasources.reporting"));

        try (AnnotationConfigApplicationContext context = context(properties)) {
            assertTrue(context.containsBean("mainDataSource"));
            assertTrue(context.containsBean("reportingDataSource"));
            DataSource main = context.getBean("mainDataSource", DataSource.class);
            DataSource reporting = context.getBean("reportingDataSource", DataSource.class);
            assertNotSame(main, reporting);
            // 'main' is the primary one - getBean(DataSource.class) finds it.
            assertEquals(main, context.getBean(DataSource.class));
        }
    }

    /** A secret source of your own - Vault, KMS, HSM - plugs in as a bean. */
    @Test
    void aSecretProviderBeanCanBePluggedIn() throws Exception {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.main.url",
                POSTGRES_URL);
        properties.put("seclume.datasources.main.username", "seclume_test");
        properties.put("seclume.datasources.main.secret.provider", "bean");
        properties.put("seclume.datasources.main.secret.bean", "myVault");

        try (AnnotationConfigApplicationContext context =
                     context(properties, OwnSecretProvider.class)) {
            try (Connection connection = context.getBean(DataSource.class).getConnection()) {
                assertTrue(connection.isValid(2));
            }
        }
    }

    @Configuration
    static class OwnSecretProvider {

        @Bean
        SecretProvider myVault() {
            return new FileSecretProvider(passwordFile, 256);
        }
    }

    /** The auto-configuration is registered - otherwise Spring Boot never finds it. */
    @Test
    void theAutoConfigurationIsRegistered() throws Exception {
        String imports = new String(getClass().getClassLoader()
                .getResourceAsStream("META-INF/spring/"
                        + "org.springframework.boot.autoconfigure.AutoConfiguration.imports")
                .readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(imports.contains(SeclumeAutoConfiguration.class.getName()), imports);
    }

    // ---- what should go wrong goes wrong loudly --------------------------

    @Test
    void aPasswordInTheConfigurationStopsTheStart() {
        Map<String, Object> properties = postgres("seclume.datasources.main");
        properties.put("spring.datasource.password", "geheim");
        Exception failure = assertThrows(Exception.class, () -> context(properties).close());
        assertTrue(messages(failure).contains("heap"), messages(failure));
    }

    @Test
    void aPasswordUnderTheDataSourceStopsTheStartToo() {
        Map<String, Object> properties = postgres("seclume.datasources.main");
        properties.put("seclume.datasources.main.password", "geheim");
        Exception failure = assertThrows(Exception.class, () -> context(properties).close());
        assertTrue(messages(failure).contains("not a seclume setting"), messages(failure));
    }

    @Test
    void anUnknownUrlSaysWhichPrefixesExist() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.main.url", "jdbc:postgresql://127.0.0.1/x");
        properties.put("seclume.datasources.main.username", "x");
        properties.put("seclume.datasources.main.secret.provider", "file");
        properties.put("seclume.datasources.main.secret.path", "/tmp/x");
        Exception failure = assertThrows(Exception.class, () -> context(properties).close());
        assertTrue(messages(failure).contains("jdbc:seclume:postgresql:"), messages(failure));
    }

    @Test
    void aMissingSecretProviderSaysWhatIsMissing() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.main.url",
                POSTGRES_URL);
        properties.put("seclume.datasources.main.username", "seclume_test");
        Exception failure = assertThrows(Exception.class, () -> context(properties).close());
        assertTrue(messages(failure).contains("secret.provider is missing"), messages(failure));
    }

    @Test
    void aMissingSecretBeanSaysSo() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.main.url",
                POSTGRES_URL);
        properties.put("seclume.datasources.main.username", "seclume_test");
        properties.put("seclume.datasources.main.secret.provider", "bean");
        properties.put("seclume.datasources.main.secret.bean", "nowhere");
        Exception failure = assertThrows(Exception.class, () -> context(properties).close());
        assertTrue(messages(failure).contains("no SecretProvider bean by that name"),
                messages(failure));
    }

    /** Without configuration the starter creates nothing - and disturbs nobody. */
    @Test
    void withoutConfigurationNothingHappens() {
        try (AnnotationConfigApplicationContext context = context(Map.of())) {
            assertEquals(0, context.getBeanNamesForType(DataSource.class).length);
        }
    }

    private static String messages(Throwable failure) {
        StringBuilder all = new StringBuilder();
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            all.append(cause.getMessage()).append('\n');
        }
        return all.toString();
    }
}
