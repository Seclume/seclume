package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Types;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * The four types PostgreSQL has and the other three do not: arrays,
 * {@code xml}, the row address, and large objects.
 *
 * <p>All four used to throw, and throwing was the right answer only for as
 * long as the alternative was guessing. Each is checked here against the real
 * server, because each is a decoding of something the server produced and
 * there is no way to know a decoder is right except by feeding it the real
 * output.
 *
 * <p>Where a type is still refused - a {@code Ref}, an XML document out of a
 * {@code varchar}, a {@code Blob} written through - that refusal is a test as
 * well. An honest "no" is part of the contract and can regress into a wrong
 * "yes" like anything else.
 */
class LocalRichTypesTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = locatePasswordFile();
        Assumptions.assumeTrue(password != null,
                "no " + TestHosts.postgresPasswordFile() + " - skipping the tests "
                        + "against a real server");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL on "
                + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        url = "jdbc:seclume:postgresql://" + TestHosts.postgres()
                + ":" + TestHosts.postgresPort() + "/" + DATABASE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    // ---- arrays -----------------------------------------------------------

    @Test
    void readsAnArrayOfEveryElementTypeItClaims() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("""
                     select array[1,2,3]::int4[]                       as ints,
                            array[1,2]::int8[]                         as longs,
                            array[1.5,2.5]::numeric[]                  as decimals,
                            array['a','b,c']::text[]                   as texts,
                            array[true,false]::bool[]                  as flags,
                            array['2024-01-31'::date]                  as dates,
                            array['3f333df6-90a4-4fda-8dd3-9485d27cee36'::uuid] as ids
                     """)) {
            assertTrue(rows.next());

            assertArrayEquals(new Integer[] {1, 2, 3}, (Integer[]) rows.getArray("ints").getArray());
            assertArrayEquals(new Long[] {1L, 2L}, (Long[]) rows.getArray("longs").getArray());
            assertArrayEquals(new BigDecimal[] {new BigDecimal("1.5"), new BigDecimal("2.5")},
                    (BigDecimal[]) rows.getArray("decimals").getArray());
            // The comma inside the second element is the case a naive split gets wrong.
            assertArrayEquals(new String[] {"a", "b,c"}, (String[]) rows.getArray("texts").getArray());
            assertArrayEquals(new Boolean[] {true, false}, (Boolean[]) rows.getArray("flags").getArray());
            assertEquals("2024-01-31",
                    ((java.sql.Date[]) rows.getArray("dates").getArray())[0].toString());
            assertEquals(UUID.fromString("3f333df6-90a4-4fda-8dd3-9485d27cee36"),
                    ((UUID[]) rows.getArray("ids").getArray())[0]);
        }
    }

    /** A null array column is a null, not an empty array - the two differ in SQL. */
    @Test
    void tellsANullArrayFromAnEmptyOne() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select null::int4[] as absent, array[]::int4[] as empty")) {
            assertTrue(rows.next());

            assertNull(rows.getArray("absent"));
            assertTrue(rows.wasNull());

            Array empty = rows.getArray("empty");
            assertNotNull(empty);
            assertFalse(rows.wasNull());
            assertEquals(0, ((Integer[]) empty.getArray()).length);
        }
    }

    /**
     * A null element inside an array, which the server writes as an unquoted
     * NULL and a string element could otherwise be confused with.
     */
    @Test
    void keepsANullElementApartFromTheWordNull() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select array['NULL', null, 'x']::text[] as mixed")) {
            assertTrue(rows.next());
            assertArrayEquals(new String[] {"NULL", null, "x"},
                    (String[]) rows.getArray(1).getArray());
        }
    }

    @Test
    void readsATwoDimensionalArray() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select array[[1,2],[3,4]]::int4[] as grid")) {
            assertTrue(rows.next());
            Object[] grid = (Object[]) rows.getArray(1).getArray();
            assertEquals(2, grid.length);
            assertArrayEquals(new Integer[] {1, 2}, (Integer[]) grid[0]);
            assertArrayEquals(new Integer[] {3, 4}, (Integer[]) grid[1]);
        }
    }

    /** The metadata has to agree with what getObject actually returns. */
    @Test
    void theMetadataCallsAnArrayAnArray() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select array[1,2]::int4[] as xs")) {
            assertEquals(Types.ARRAY, rows.getMetaData().getColumnType(1));
            assertEquals("_int4", rows.getMetaData().getColumnTypeName(1));
            assertEquals("java.sql.Array", rows.getMetaData().getColumnClassName(1));
            assertTrue(rows.next());
            assertTrue(rows.getObject(1) instanceof Array,
                    "getObject must return what the metadata promised");
        }
    }

    @Test
    void servesArrayElementsAsAResultSet() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select array[10,20,30]::int4[]")) {
            assertTrue(rows.next());
            try (ResultSet elements = rows.getArray(1).getResultSet()) {
                assertTrue(elements.next());
                assertEquals(1, elements.getLong(1));
                assertEquals(10, elements.getInt(2));
                assertTrue(elements.next());
                assertTrue(elements.next());
                assertEquals(3, elements.getLong("INDEX"));
                assertEquals(30, elements.getInt("VALUE"));
                assertFalse(elements.next());
            }
        }
    }

    /** Asking a column that is not an array for one is a mistake, and says so. */
    @Test
    void refusesToReadANonArrayAsAnArray() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select 1::int4 as n")) {
            assertTrue(rows.next());
            SQLException refusal = assertThrows(SQLException.class, () -> rows.getArray(1));
            assertTrue(refusal.getMessage().contains("not an array"), refusal.getMessage());
        }
    }

    // ---- xml --------------------------------------------------------------

    @Test
    void readsAnXmlColumn() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select '<invoice n=\"7\"><line>a</line></invoice>'::xml as doc")) {
            assertEquals(Types.SQLXML, rows.getMetaData().getColumnType(1));
            assertTrue(rows.next());

            SQLXML document = rows.getSQLXML("doc");
            assertEquals("<invoice n=\"7\"><line>a</line></invoice>", document.getString());
            assertEquals("<invoice n=\"7\"><line>a</line></invoice>",
                    new String(document.getBinaryStream().readAllBytes(), StandardCharsets.UTF_8));
            assertNotNull(document.getSource(javax.xml.transform.stream.StreamSource.class));

            // Read-only, and the source the driver will not build.
            assertThrows(SQLFeatureNotSupportedException.class, () -> document.setString("<a/>"));
            assertThrows(SQLFeatureNotSupportedException.class,
                    () -> document.getSource(javax.xml.transform.dom.DOMSource.class));

            document.free();
            assertThrows(SQLException.class, document::getString);
        }
    }

    /** A varchar that happens to hold XML is still a varchar. */
    @Test
    void refusesToCallAVarcharXml() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select '<a/>'::varchar as looks_like_xml")) {
            assertTrue(rows.next());
            SQLException refusal = assertThrows(SQLException.class, () -> rows.getSQLXML(1));
            assertTrue(refusal.getMessage().contains("not xml"), refusal.getMessage());
        }
    }

    @Test
    void aNullXmlColumnIsNull() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select null::xml")) {
            assertTrue(rows.next());
            assertNull(rows.getSQLXML(1));
            assertTrue(rows.wasNull());
        }
    }

    // ---- the row address --------------------------------------------------

    @Test
    void readsTheRowAddress() throws Exception {
        try (Connection connection = connect();
             Statement ddl = connection.createStatement()) {
            ddl.execute("drop table if exists zl_rich_rows");
            ddl.execute("create table zl_rich_rows (id int primary key, name text)");
            ddl.execute("insert into zl_rich_rows values (1, 'one'), (2, 'two')");
            try {
                RowId first;
                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery(
                             "select ctid, id from zl_rich_rows order by id")) {
                    assertEquals(Types.ROWID, rows.getMetaData().getColumnType(1));
                    assertTrue(rows.next());
                    first = rows.getRowId(1);
                    assertNotNull(first);
                    // The server's own spelling of an address: (block,offset).
                    assertTrue(first.toString().matches("\\(\\d+,\\d+\\)"), first.toString());
                    assertTrue(rows.next());
                    assertFalse(first.equals(rows.getRowId("ctid")),
                            "two rows must not share an address");
                }

                // And it addresses the row it came from.
                try (PreparedStatement byAddress = connection.prepareStatement(
                        "select id from zl_rich_rows where ctid = ?::tid")) {
                    byAddress.setString(1, first.toString());
                    try (ResultSet rows = byAddress.executeQuery()) {
                        assertTrue(rows.next());
                        assertEquals(1, rows.getInt(1));
                    }
                }

                assertEquals(java.sql.RowIdLifetime.ROWID_VALID_TRANSACTION,
                        connection.getMetaData().getRowIdLifetime());
            } finally {
                ddl.execute("drop table if exists zl_rich_rows");
            }
        }
    }

    @Test
    void refusesToCallAnOrdinaryColumnARowAddress() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select 'x'::text")) {
            assertTrue(rows.next());
            SQLException refusal = assertThrows(SQLException.class, () -> rows.getRowId(1));
            assertTrue(refusal.getMessage().contains("ctid"), refusal.getMessage());
        }
    }

    // ---- large objects ----------------------------------------------------

    /**
     * A large object round trip: create, reference from a row, read it back
     * as a {@code Blob} and as a stream, then unlink it.
     *
     * <p>The content is three megabytes so that the chunking is exercised -
     * a one-chunk object would prove nothing about the loop.
     */
    @Test
    void readsALargeObjectThroughItsOid() throws Exception {
        byte[] content = new byte[3 * 1024 * 1024 + 17];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) (i * 31);
        }

        try (Connection connection = connect();
             Statement ddl = connection.createStatement()) {
            ddl.execute("drop table if exists zl_rich_lo");
            ddl.execute("create table zl_rich_lo (id int primary key, body oid)");

            PgLargeObjects objects = connection.unwrap(PgLargeObjects.class);
            assertTrue(connection.isWrapperFor(PgLargeObjects.class));
            long oid = objects.create(content);
            try {
                try (PreparedStatement insert = connection.prepareStatement(
                        "insert into zl_rich_lo values (1, ?)")) {
                    insert.setLong(1, oid);
                    insert.executeUpdate();
                }

                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery("select body from zl_rich_lo")) {
                    assertTrue(rows.next());

                    Blob blob = rows.getBlob(1);
                    assertEquals(content.length, blob.length());
                    assertArrayEquals(new byte[] {content[0], content[1], content[2]},
                            blob.getBytes(1, 3));
                    // The last byte, which is where an off-by-one in the chunking shows.
                    assertArrayEquals(new byte[] {content[content.length - 1]},
                            blob.getBytes(content.length, 1));
                    assertArrayEquals(content, blob.getBinaryStream().readAllBytes());

                    assertThrows(SQLFeatureNotSupportedException.class,
                            () -> blob.setBytes(1, new byte[] {0}));
                }

                // The same bytes through the stream hook, which is the path an
                // application takes when it does not want the Blob interface.
                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery("select body from zl_rich_lo")) {
                    assertTrue(rows.next());
                    try (InputStream stream = rows.getBinaryStream(1)) {
                        assertArrayEquals(content, stream.readAllBytes());
                    }
                }

                assertEquals(content.length, objects.length(oid));
                assertArrayEquals(content, objects.read(oid));
                assertArrayEquals(content, objects.stream(oid).readAllBytes());
            } finally {
                objects.delete(oid);
                ddl.execute("drop table if exists zl_rich_lo");
            }

            // Unlinked means gone, and reading it is an error rather than an
            // empty answer - the distinction a caller needs to see.
            assertThrows(SQLException.class, () -> objects.read(oid));
        }
    }

    /**
     * {@code createBlob} stays refused, and the refusal names the way that
     * does work. A factory method that quietly created a database row would
     * be the worse of the two answers.
     */
    @Test
    void createBlobExplainsItselfRatherThanLeakingAnObject() throws Exception {
        try (Connection connection = connect()) {
            SQLException refusal = assertThrows(SQLException.class, connection::createBlob);
            assertTrue(refusal.getMessage().contains("PgLargeObjects"), refusal.getMessage());
        }
    }

    /** A REF has no type to point at in any of the four servers, and still says so. */
    @Test
    void aRefIsStillRefused() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select 1")) {
            assertTrue(rows.next());
            assertThrows(SQLFeatureNotSupportedException.class, () -> rows.getRef(1));
        }
    }

    private static Path locatePasswordFile() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static boolean reachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
