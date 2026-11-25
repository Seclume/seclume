package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import space.seclume.SensitiveParameters;
import space.seclume.tck.TestHosts;

/**
 * A value bound with setSensitive came back as a String on the error path:
 * PostgreSQL quotes it in {@code DETAIL: Key (signing_key)=(...) already
 * exists}, and the exception carried it to every log that printed it. The
 * receive buffer is masked before the error is decoded.
 */
class LocalSensitiveErrorTest {

    private static final String SECRET = "whsec_DECOY_sensitive_echo_7f3a";

    @Test
    void aUniqueViolationDoesNotQuoteTheSensitiveValue() throws Exception {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + host);
        }
        String url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace('\\', '/');
        try (Connection connection = DriverManager.getConnection(url);
             Arena arena = Arena.ofConfined()) {
            try (Statement ddl = connection.createStatement()) {
                ddl.execute("create temporary table hooks (signing_key text unique)");
            }
            byte[] bytes = SECRET.getBytes(StandardCharsets.US_ASCII);
            MemorySegment value = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, value, java.lang.foreign.ValueLayout.JAVA_BYTE, 0,
                    bytes.length);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into hooks values (?)")) {
                insert.unwrap(SensitiveParameters.class).setSensitive(1, value);
                insert.executeUpdate();
                insert.unwrap(SensitiveParameters.class).setSensitive(1, value);
                SQLException duplicate = assertThrows(SQLException.class, insert::executeUpdate);
                StringWriter everything = new StringWriter();
                duplicate.printStackTrace(new PrintWriter(everything));
                assertTrue(everything.toString().contains("23505")
                        || "23505".equals(duplicate.getSQLState()), everything.toString());
                assertFalse(everything.toString().contains(SECRET),
                        "the sensitive value is in the exception: " + everything);
                // DETAIL: Key (signing_key)=(...) already exists - where it was.
                for (Throwable t = duplicate; t != null; t = t.getCause()) {
                    if (t instanceof space.seclume.postgresql.PgException pg) {
                        assertTrue(pg.detail() != null && pg.detail().contains("already exists"),
                                String.valueOf(pg.detail()));
                        assertFalse(pg.detail().contains(SECRET), "in DETAIL: " + pg.detail());
                    }
                }
            }
        }
    }
}
