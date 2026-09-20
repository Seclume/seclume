package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;

import java.sql.PreparedStatement;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.RoundTrips;

/**
 * LOBs, against a <b>real</b> Oracle.
 *
 * <p>This is the one that decides. The layout of a locator in a row and the
 * shape of function 96 were not obvious from the specification of anything else; a synthetic test
 * would only prove that the expectation was copied correctly.
 * Only the server can say whether the call is right - and with Oracle a wrong
 * field is not an error message but silence.
 *
 * <p>Skipped, not failed, when there is no listener: the container is not
 * always up.
 */
class LocalOracleLobTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/" + SERVICE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    /**
     * Leaves the schema as it was found.
     *
     * <p>Not tidiness: a leftover table makes Flyway refuse to migrate, and
     * the Spring Data suite then fails eight tests with a message that says
     * nothing about LOBs. Cost an afternoon once is one time too many.
     */
    @AfterAll
    static void cleanUp() throws SQLException {
        if (url == null) {
            return;
        }
        try (Connection connection = connect()) {
            OracleTestSchema.clean(connection);
        }
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    private static void drop(Connection connection, String table) {
        try (Statement statement = connection.createStatement()) {
            // "purge": without it the table lands in the recycle bin and still
            // counts as an object, which is enough for Flyway to refuse the
            // next migration - and the error it throws says nothing about LOBs.
            statement.execute("drop table " + table + " purge");
        } catch (SQLException e) {
            // ORA-00942: it was not there, which is what was wanted.
        }
    }

    /**
     * Fills the table with SQL literals, not with binds.
     *
     * <p>Deliberate: <b>writing</b> a LOB through a bind is not supported yet,
     * and a fixture that depends on it would blame the read path for a fault
     * of the write path. Measured on this server - a bind into a CLOB column
     * leaves the answer half-read and the next call finds the connection out
     * of step.
     */
    private static void createAndFill(Connection connection, String text, String hexBytes)
            throws SQLException {
        drop(connection, "zl_lob");
        try (Statement statement = connection.createStatement()) {
            statement.execute("create table zl_lob (id number, c clob, b blob)");
            statement.execute("insert into zl_lob values (1, to_clob('" + text + "'), "
                    + "to_blob(hextoraw('" + hexBytes + "')))");
        }
        connection.commit();
    }

    /**
     * 200 000 characters and 200 000 bytes, written through binds.
     *
     * <p>This used to be built on the server with SQL, because writing a large
     * LOB broke the connection. It no longer does - so the fixture writes the
     * same way an application would, and the test covers both directions.
     */
    private static void fillLarge(Connection connection) throws SQLException {
        drop(connection, "zl_lob");
        try (Statement statement = connection.createStatement()) {
            statement.execute("create table zl_lob (id number, c clob, b blob)");
        }
        byte[] bytes = new byte[200_000]; // seclume-allow: test payload, not a secret
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i % 251);
        }
        try (PreparedStatement insert =
                     connection.prepareStatement("insert into zl_lob values (1, ?, ?)")) {
            insert.setString(1, "A".repeat(200_000));
            insert.setBytes(2, bytes);
            insert.executeUpdate();
        }
        connection.commit();

        // A fixture that builds the wrong thing blames the driver for its own
        // mistake. So it says out loud what it built.
        try (Statement q = connection.createStatement();
             ResultSet r = q.executeQuery(
                     "select dbms_lob.getlength(c), dbms_lob.getlength(b) from zl_lob")) {
            r.next();
            assertEquals(200_000, r.getLong(1), "fixture: the CLOB is not 200000 characters");
            assertEquals(200_000, r.getLong(2), "fixture: the BLOB is not 200000 bytes");
        }
    }

    /**
     * The long case: more than a chunk, more than a packet.
     *
     * <p>This is where a driver that stops after the first packet gets caught.
     * It does not fail loudly - it returns the first 8060 characters and calls
     * them the value.
     */
    @Test
    void readsALobThatSpansManyPackets() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            fillLarge(connection);

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                assertTrue(rows.next());
                String read = rows.getString(1);
                assertEquals(200_000, read.length(), "the CLOB came back short");
                assertEquals("A".repeat(200_000), read);
                byte[] bytes = rows.getBytes(2);
                assertEquals(200_000, bytes.length, "the BLOB came back short");
                assertEquals((byte) (199_999 % 251), bytes[199_999]);
            }
        }
    }

    /** A LOB that is there but empty, and one that is not there at all. */
    @Test
    void tellsEmptyFromNull() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            drop(connection, "zl_lob");
            try (Statement statement = connection.createStatement()) {
                statement.execute("create table zl_lob (id number, c clob, b blob)");
                statement.execute("insert into zl_lob values (1, empty_clob(), empty_blob())");
                statement.execute("insert into zl_lob values (2, null, null)");
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "select c, b from zl_lob order by id")) {
                assertTrue(rows.next());
                assertEquals("", rows.getString(1));
                assertArrayEquals(new byte[0], rows.getBytes(2));

                assertTrue(rows.next());
                assertNull(rows.getString(1));
                assertTrue(rows.wasNull());
                assertNull(rows.getBytes(2));
            }
        }
    }

    /**
     * Writing through a bind - the short case.
     *
     * <p>This used to leave the answer half-read and the connection out of
     * step. Whether the connect fix cured that too is exactly what this asks.
     */
    @Test
    void writesASmallClobAndBlobThroughBinds() throws Exception {
        byte[] bytes = {1, 2, 3, 'b', 'i', 'n'};
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            drop(connection, "zl_lob");
            try (Statement statement = connection.createStatement()) {
                statement.execute("create table zl_lob (id number, c clob, b blob)");
            }
            try (PreparedStatement insert =
                         connection.prepareStatement("insert into zl_lob values (1, ?, ?)")) {
                insert.setString(1, "geschrieben per Bindewert");
                insert.setBytes(2, bytes);
                insert.executeUpdate();
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                assertTrue(rows.next());
                assertEquals("geschrieben per Bindewert", rows.getString(1));
                assertArrayEquals(bytes, rows.getBytes(2));
            }
        }
    }

    /** Writing through a bind - larger than one packet. */
    @Test
    void writesALargeClobThroughABind() throws Exception {
        String text = "A".repeat(200_000);
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            drop(connection, "zl_lob");
            try (Statement statement = connection.createStatement()) {
                statement.execute("create table zl_lob (id number, c clob, b blob)");
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_lob values (1, ?, empty_blob())")) {
                insert.setString(1, text);
                insert.executeUpdate();
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c from zl_lob")) {
                assertTrue(rows.next());
                assertEquals(200_000, rows.getString(1).length());
            }
        }
    }

    /**
     * A slice costs a slice, not the whole value.
     *
     * <p>That is the whole point of {@code Clob}: a value that need not fit in
     * memory. Asking for 4096 characters out of 200 000 must fetch 4096 - one
     * round trip - and not quietly pull the rest along.
     */
    @Test
    void aSliceCostsOneRoundTripAndBringsOnlyTheSlice() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            fillLarge(connection);

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                assertTrue(rows.next());

                Clob clob = rows.getClob(1);

                // The length is an operation of its own, not the whole value.
                long beforeLength = RoundTrips.of(connection);
                assertEquals(200_000, clob.length(), "the length came back wrong");
                assertEquals(1, RoundTrips.of(connection) - beforeLength,
                        "a length is one round trip, not the whole value");

                long before = RoundTrips.of(connection);
                String part = clob.getSubString(1_001, 4_096);
                long spent = RoundTrips.of(connection) - before;
                assertEquals(4_096, part.length(), "the slice came back the wrong size");
                assertEquals("A".repeat(4_096), part);
                assertEquals(1, spent, "a slice is one round trip");

                Blob blob = rows.getBlob(2);
                byte[] bytes = blob.getBytes(1_001, 100);
                assertEquals(100, bytes.length);
                assertEquals((byte) (1_000 % 251), bytes[0]);
            }
        }
    }

    /** The stream reads in blocks and stops at the end, without asking for a length. */
    @Test
    void readsALobAsAStream() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            fillLarge(connection);

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                assertTrue(rows.next());

                long characters = 0;
                try (java.io.Reader reader = rows.getCharacterStream(1)) {
                    char[] buffer = new char[1024];
                    for (int read; (read = reader.read(buffer)) >= 0; ) {
                        characters += read;
                    }
                }
                assertEquals(200_000, characters, "the reader stopped early");

                long bytes = 0;
                try (java.io.InputStream in = rows.getBinaryStream(2)) {
                    byte[] buffer = new byte[1024];
                    for (int read; (read = in.read(buffer)) >= 0; ) {
                        bytes += read;
                    }
                }
                assertEquals(200_000, bytes, "the stream stopped early");
            }
        }
    }

    /** A NULL LOB stays null, even through the Clob door. */
    @Test
    void aNullLobHasNoClob() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            drop(connection, "zl_lob");
            try (Statement statement = connection.createStatement()) {
                statement.execute("create table zl_lob (id number, c clob, b blob)");
                statement.execute("insert into zl_lob values (1, null, null)");
            }
            connection.commit();
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                assertTrue(rows.next());
                assertNull(rows.getClob(1));
                assertTrue(rows.wasNull());
                assertNull(rows.getBlob(2));
                assertNull(rows.getCharacterStream(1));
            }
        }
    }

    /**
     * Writing through the stream setters - the ones frameworks reach for.
     *
     * <p>They materialise the value rather than streaming it, which is said
     * out loud in the code. Refusing them would turn a working Hibernate
     * mapping into a stack trace, and that is the worse trade.
     */
    @Test
    void writesThroughStreamSetters() throws Exception {
        String text = "B".repeat(120_000);
        byte[] bytes = new byte[120_000]; // seclume-allow: test payload
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i % 97);
        }
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            drop(connection, "zl_lob");
            try (Statement statement = connection.createStatement()) {
                statement.execute("create table zl_lob (id number, c clob, b blob)");
            }
            try (PreparedStatement insert =
                         connection.prepareStatement("insert into zl_lob values (1, ?, ?)")) {
                insert.setCharacterStream(1, new java.io.StringReader(text));
                insert.setBinaryStream(2, new java.io.ByteArrayInputStream(bytes));
                insert.executeUpdate();
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                assertTrue(rows.next());
                assertEquals(text, rows.getString(1));
                assertArrayEquals(bytes, rows.getBytes(2));
            }
        }
    }

    /**
     * The pattern frameworks use: create, fill, bind.
     *
     * <p>`createClob` used to throw, which turned a working Hibernate mapping
     * into a stack trace. The value lives in the driver until it is sent; what
     * it is <b>not</b> is a server-side temporary LOB, and the code says so.
     */
    @Test
    void createsFillsAndBindsALob() throws Exception {
        String text = "erzeugt, gefuellt, gebunden — " + "C".repeat(50_000);
        byte[] bytes = new byte[50_000]; // seclume-allow: test payload
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i % 53);
        }
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            drop(connection, "zl_lob");
            try (Statement statement = connection.createStatement()) {
                statement.execute("create table zl_lob (id number, c clob, b blob)");
            }

            Clob clob = connection.createClob();
            assertEquals(0, clob.length(), "a fresh Clob has no data");
            clob.setString(1, text);
            assertEquals(text.length(), clob.length());
            assertEquals("erzeugt", clob.getSubString(1, 7));

            Blob blob = connection.createBlob();
            blob.setBytes(1, bytes);
            assertEquals(bytes.length, blob.length());

            try (PreparedStatement insert =
                         connection.prepareStatement("insert into zl_lob values (1, ?, ?)")) {
                insert.setClob(1, clob);
                insert.setBlob(2, blob);
                insert.executeUpdate();
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                assertTrue(rows.next());
                assertEquals(text, rows.getString(1));
                assertArrayEquals(bytes, rows.getBytes(2));
            }
        }
    }

    /** The driver has to say CLOB and BLOB, or Hibernate maps them wrong. */
    @Test
    void describesTheColumns() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            createAndFill(connection, "x", "01");
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c, b from zl_lob")) {
                ResultSetMetaData meta = rows.getMetaData();
                assertEquals(Types.CLOB, meta.getColumnType(1));
                assertEquals("CLOB", meta.getColumnTypeName(1));
                assertEquals(Types.BLOB, meta.getColumnType(2));
                assertEquals("BLOB", meta.getColumnTypeName(2));
            }
        }
    }

    /**
     * The count that keeps the promise: a LOB costs <b>one</b> round trip, and
     * its length costs none.
     *
     * <p>The length travels in the row next to the locator. A driver that asks
     * the server for it pays a round trip the value has already covered - and
     * that is the kind of cost nobody notices until someone counts.
     */
    @Test
    void aLobCostsOneRoundTrip() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            fillLarge(connection);

            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select c from zl_lob")) {
                assertTrue(rows.next());
                long before = RoundTrips.of(connection);
                assertEquals(200_000, rows.getString(1).length());
                long spent = RoundTrips.of(connection) - before;
                assertEquals(1, spent, "a whole LOB in one round trip");
            }
        }
    }
}
