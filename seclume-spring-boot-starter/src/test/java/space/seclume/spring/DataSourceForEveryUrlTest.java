package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/**
 * Every URL prefix finds its driver - without a server.
 *
 * <p>This is the promise of the starter taken literally: the URL decides, and
 * nothing else has to be configured. It runs against no database because
 * building a {@code DataSource} opens nothing; the pool only connects when
 * somebody asks for a connection, or when warmup is switched on.
 *
 * <p>The drivers are optional dependencies and each one is loaded from an
 * inner class of its own, so a missing module has to name itself rather than
 * fall out as a {@code NoClassDefFoundError}. Here they are all present, which
 * is what makes the class names checkable.
 */
class DataSourceForEveryUrlTest {

    private static Path secretFile;

    @BeforeAll
    static void writeASecret() throws IOException {
        secretFile = Files.createTempFile("seclume-test", ".secret");
        Files.write(secretFile, "not-a-real-password".getBytes(StandardCharsets.UTF_8));
        secretFile.toFile().deleteOnExit();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "jdbc:seclume:postgresql://host:5432/db,"
                + " space.seclume.postgresql.jdbc.SeclumeDataSource",
        "jdbc:seclume:mysql://host:3306/db,     space.seclume.mysql.jdbc.MyDataSource",
        "jdbc:seclume:mariadb://host:3306/db,   space.seclume.mysql.jdbc.MyDataSource",
        "jdbc:seclume:sqlserver://host:1433/db,"
                + " space.seclume.sqlserver.jdbc.TdsDataSource",
        "jdbc:seclume:mssql://host:1433/db,"
                + " space.seclume.sqlserver.jdbc.TdsDataSource",
        "jdbc:seclume:oracle://host:1521/FREEPDB1,"
                + " space.seclume.oracle.jdbc.OraDataSource",
    })
    void everyPrefixFindsItsDriver(String url, String expected) {
        DataSource source = SeclumeDataSources.create("main", properties(url), null);
        assertEquals(expected, source.getClass().getName());
    }

    @Test
    void anUnknownPrefixNamesAllOfThem() {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> SeclumeDataSources.create("main",
                        properties("jdbc:oracle:thin:@host:1521/FREEPDB1"), null));
        for (String prefix : new String[] {"postgresql", "mysql", "mariadb", "sqlserver",
                                           "oracle"}) {
            assertTrue(failure.getMessage().contains("jdbc:seclume:" + prefix + ":"),
                    "the message does not name " + prefix + ": " + failure.getMessage());
        }
    }

    private static SeclumeProperties.DataSourceProperties properties(String url) {
        SeclumeProperties.DataSourceProperties properties =
                new SeclumeProperties.DataSourceProperties();
        properties.setUrl(url);
        properties.setUsername("seclume_test");
        properties.getSecret().setProvider("file");
        properties.getSecret().setPath(secretFile.toString());
        return properties;
    }
}
