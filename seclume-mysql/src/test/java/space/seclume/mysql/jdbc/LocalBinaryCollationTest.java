package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Text in a binary collation is text.
 *
 * <p>MySQL sets the BINARY flag on a column whose collation is a
 * {@code _bin} one - {@code utf8mb4_bin}, the usual way to make a column case
 * sensitive, and the collation of {@code information_schema}'s own names.
 * {@code getObject} decided by that flag and returned such text as
 * {@code byte[]}; Liquibase, reading table names out of {@code getTables},
 * cast one to {@code String} and stopped. What decides is the character set:
 * 63 is binary, and nothing else is.
 */
@Timeout(60)
class LocalBinaryCollationTest {

    private static final String HOST =
            System.getProperty("seclume.mysql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test"
                + "?user=seclume_test&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void aBinCollationGivesAStringAndBinaryGivesBytes() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_bin_collation");
            statement.execute("create table zl_bin_collation ("
                    + "code varchar(20) character set utf8mb4 collate utf8mb4_bin, "
                    + "raw varbinary(20))");
            statement.executeUpdate("insert into zl_bin_collation values ('Grüße', x'00ff10')");
            try (ResultSet rows = statement.executeQuery(
                    "select code, raw from zl_bin_collation")) {
                rows.next();
                assertEquals("Grüße", assertInstanceOf(String.class, rows.getObject(1)));
                assertArrayEquals(new byte[] {0, (byte) 0xff, 0x10},
                        assertInstanceOf(byte[].class, rows.getObject(2)));
            }
            // And information_schema, which is where Liquibase met it.
            try (ResultSet tables = connection.getMetaData().getTables(
                    "seclume_test", null, "zl_bin_collation", null)) {
                tables.next();
                assertEquals("zl_bin_collation",
                        assertInstanceOf(String.class, tables.getObject("TABLE_NAME")));
                assertEquals("seclume_test",
                        new String(String.valueOf(tables.getObject("TABLE_CAT"))
                                .getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8));
            }
            statement.execute("drop table zl_bin_collation");
        }
    }
}
