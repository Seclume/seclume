package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.RowId;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Types;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * {@code ROWID} and {@code XMLType}: two types that are not length-prefixed
 * values on the wire, and that each broke every column behind them.
 *
 * <p>A rowid arrives as five numbers of the protocol's own width; its leading
 * byte was taken for a length - fourteen where the five take eleven - and the
 * next column lost three bytes. An {@code XMLType} arrives as a pickled
 * object, and its description carries an object id, a schema and a type name,
 * each a length and then the bytes - read as bare blocks, the description
 * went out of step and the result looked empty. The server is the reference
 * for both: {@code rowidtochar} and {@code getClobVal()}. And a column behind
 * each shows the row stayed in step.
 */
@Timeout(60)
class LocalRowidAndXmlTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = System.getProperty("seclume.oracle.host",
                space.seclume.tck.TestHosts.database());
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle on " + host + ":" + port);
        }
        url = "jdbc:seclume:oracle://" + host + ":" + port + "/"
                + System.getProperty("seclume.oracle.service", "FREEPDB1")
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    @Test
    void aRowidReadsAsOracleWritesItAndFindsItsRowAgain() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("begin execute immediate 'drop table zl_rowid purge'; "
                    + "exception when others then null; end;");
            statement.execute("create table zl_rowid (n number, s varchar2(10))");
            statement.execute("insert into zl_rowid values (1, 'one')");
            statement.execute("insert into zl_rowid values (2, 'two')");
            RowId second = null;
            try (ResultSet rows = statement.executeQuery(
                    "select rowid, rowidtochar(rowid), n, s from zl_rowid order by n")) {
                assertEquals(Types.ROWID, rows.getMetaData().getColumnType(1));
                assertEquals("ROWID", rows.getMetaData().getColumnTypeName(1));
                int seen = 0;
                while (rows.next()) {
                    seen++;
                    assertEquals(rows.getString(2), rows.getString(1));
                    assertEquals(rows.getString(2), rows.getRowId(1).toString());
                    assertTrue(rows.getObject(1) instanceof RowId);
                    assertEquals(seen, rows.getInt(3), "the columns behind the rowid moved");
                    assertEquals(seen == 1 ? "one" : "two", rows.getString(4));
                    second = rows.getRowId(1);
                }
                assertEquals(2, seen);
            }
            try (PreparedStatement find = connection.prepareStatement(
                    "select n from zl_rowid where rowid = ?")) {
                find.setRowId(1, second);
                try (ResultSet rows = find.executeQuery()) {
                    assertTrue(rows.next(), "the rowid did not find its row");
                    assertEquals(2, rows.getInt(1));
                }
            }
            statement.execute("drop table zl_rowid purge");
        }
    }

    @Test
    void xmlTypeReadsAsTheDocumentAndKeepsTheRowInStep() throws Exception {
        String document = "<order id=\"7\"><item qty=\"2\">Grüße &amp; more</item></order>";
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select xmltype('" + document + "') x, "
                     + "xmltype('" + document + "').getClobVal() c, 42 n from dual")) {
            assertTrue(rows.next());
            assertEquals(Types.SQLXML, rows.getMetaData().getColumnType(1));
            assertEquals("SYS.XMLTYPE", rows.getMetaData().getColumnTypeName(1));      // as ojdbc
            String server = rows.getString(2);
            assertEquals(server, rows.getString(1));
            SQLXML xml = rows.getSQLXML(1);
            assertEquals(server, xml.getString());
            assertTrue(rows.getObject(1) instanceof SQLXML);
            assertEquals(42, rows.getInt(3), "the column behind the XMLType moved");
        }
    }
}
