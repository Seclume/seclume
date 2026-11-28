package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
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
 * MySQL quotes a duplicate value in the error message itself -
 * {@code Duplicate entry '...' for key ...} - and a value bound with
 * setSensitive became part of getMessage(), a String in every log. The
 * error packet is masked before it is decoded.
 */
class LocalSensitiveErrorTest {

    private static final String SECRET = "whsec_DECOY_mysql_echo_4c1d";

    @Test
    void aDuplicateEntryDoesNotQuoteTheSensitiveValue() throws Exception {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        String host = TestHosts.database();
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + host + ":" + port);
        }
        String url = "jdbc:seclume:mysql://" + host + ":" + port + "/seclume_test?user=seclume_test"
                + "&tls=off&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
        try (Connection connection = DriverManager.getConnection(url);
             Arena arena = Arena.ofConfined()) {
            try (Statement ddl = connection.createStatement()) {
                ddl.execute("create temporary table hooks (signing_key varchar(64) unique)");
            }
            byte[] bytes = SECRET.getBytes(StandardCharsets.US_ASCII);
            MemorySegment value = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, value, ValueLayout.JAVA_BYTE, 0, bytes.length);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into hooks values (?)")) {
                insert.unwrap(SensitiveParameters.class).setSensitive(1, value);
                insert.executeUpdate();
                insert.unwrap(SensitiveParameters.class).setSensitive(1, value);
                SQLException duplicate = assertThrows(SQLException.class, insert::executeUpdate);
                assertEquals(1062, duplicate.getErrorCode(), duplicate.getMessage());
                StringWriter everything = new StringWriter();
                duplicate.printStackTrace(new PrintWriter(everything));
                assertFalse(everything.toString().contains(SECRET),
                        "the sensitive value is in the exception: " + everything);
            }
        }
    }
}
