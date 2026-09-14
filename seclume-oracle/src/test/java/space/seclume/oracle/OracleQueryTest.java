package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.TtcResult;
import space.seclume.secret.FileSecretProvider;

/**
 * Statements against a <b>real</b> Oracle instance.
 *
 * <p>Everything up to here was checked against a recording. That proves the
 * driver reads what one client once sent - not that a server accepts what the
 * driver sends. This is where that gets decided.
 *
 * <p>Deliberately with more than one row: the row header carries a bit vector
 * saying which columns keep the value of the row before, and the server does
 * not send those again. A single-row query never touches that, and a driver
 * that ignores it reads every row after the first shifted - plausible wrong
 * data rather than an error.
 */
class OracleQueryTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", "db.example.invalid");
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
    }

    private static OracleSession open() throws Exception {
        return OracleSession.open(new OracleSession.Settings(HOST, PORT, SERVICE, USER,
                new FileSecretProvider(passwordFile, 256)));
    }

    @Test
    void readsOneRow() throws Exception {
        try (OracleSession session = open()) {
            List<String> values = new ArrayList<>();
            TtcResult result = session.query("select 42 as answer, 'abc' as text from dual",
                    row -> {
                        values.add(row.text(0));
                        values.add(row.text(1));
                    });
            assertEquals(List.of("ANSWER", "TEXT"),
                    result.columns().stream().map(OracleColumn::name).toList());
            assertEquals(List.of("42", "abc"), values);
            System.out.println("Oracle answered: " + values);
        }
    }

    /**
     * Several rows - and thereby the bit vector of the row header.
     *
     * <p>The server answers with a first block of rows and waits for a fetch
     * call for the rest. How large that block is sits in the {@code al8i4}
     * vector, which this driver still copies verbatim from a recording - so it
     * is currently two. Fetching beyond the first block is the next piece of
     * work; until then this test checks what does work, and it checks the part
     * that matters most: the second row.
     *
     * <p>The second column has the same value in every row, so the server does
     * not send it again - it only sets a bit in the row header. A driver that
     * ignores that reads the second row shifted and gets plausible wrong data
     * rather than an error.
     */
    @Test
    void readsASecondRowWithoutRepeatedValues() throws Exception {
        try (OracleSession session = open()) {
            List<String> ids = new ArrayList<>();
            List<String> constant = new ArrayList<>();
            TtcResult result = session.query("""
                    select level as n, 'same' as unchanged
                    from dual connect by level <= 20""", row -> {
                        ids.add(row.text(0));
                        constant.add(row.text(1));
                    });
            System.out.println("Oracle sent " + ids.size() + " rows, "
                    + "the repeated column arrived " + constant.size() + " times");
            assertEquals(20, ids.size(), "not all rows arrived: " + ids.size());
            assertEquals("1", ids.get(0));
            assertEquals("2", ids.get(1));
            assertEquals("20", ids.get(19));
            assertTrue(constant.stream().allMatch("same"::equals),
                    "the unchanged column drifted: " + constant);
        }
    }

    /**
     * A failing statement has to be recognisable as one.
     *
     * <p>Oracle reports the end of a result the same way it reports a failure:
     * as an error message, and only the number tells them apart. And before
     * the error it sends a <b>marker</b> and waits for one back - the
     * out-of-band handshake that {@code OracleSession.drainMarkers} answers.
     */
    @Test
    void reportsAFailingStatement() throws Exception {
        try (OracleSession session = open()) {
            TtcResult result = session.query("select * from zl_does_not_exist", null);
            System.out.println("Oracle error number: " + result.errorNumber());
            // ORA-00942: table or view does not exist
            assertEquals(942, result.errorNumber());
            assertTrue(result.isFailure(), "the failure was not recognised as one");
            assertEquals(0, result.rowCount());
        }
    }

    /** And a good statement must not look like a failure. */
    @Test
    void aGoodStatementReportsNoError() throws Exception {
        try (OracleSession session = open()) {
            TtcResult result = session.query("select 1 from dual", null);
            // 1403 is the end of the result, not a failure - the driver has
            // to tell those two apart, and this is where that is checked.
            assertEquals(1403, result.errorNumber());
            assertFalse(result.isFailure(),
                    "a successful query was reported as a failure");
        }
    }

    /**
     * More rows than the server sends in one block.
     *
     * <p>Oracle answers with a first block and then waits to be asked. The
     * fetch call names the cursor the server opened and says how many more rows
     * are wanted; without it a large result silently ends after the first
     * block - and "silently" is the dangerous part.
     */
    @Test
    void fetchesBeyondTheFirstBlock() throws Exception {
        try (OracleSession session = open()) {
            List<String> ids = new ArrayList<>();
            TtcResult result = session.query(
                    "select level as n from dual connect by level <= 250",
                    row -> ids.add(row.text(0)));
            System.out.println("Oracle sent " + ids.size() + " rows in total, "
                    + "fetched from cursor " + result.cursorId());
            assertEquals(250, ids.size(), "the fetch call did not bring the rest");
            assertEquals("1", ids.get(0));
            assertEquals("250", ids.get(249));
        }
    }

    /**
     * A wide query - the shape that used to lose its rows.
     *
     * <p>A real table column is described with a character set, a maximum size
     * and an object id where a computed column has zeroes, and the first
     * parser read two fields that do not exist. On the recording it was built
     * from - {@code select 42, 'abc' from dual} - every one of those fields
     * was zero and one byte wide, so the wrong reading fit the bytes exactly
     * and consumed the rows behind the description.
     *
     * <p>What settled it was a recording over a table with a
     * {@code NUMBER(9,2)}, a {@code VARCHAR2(40)} and a {@code DATE} side by
     * side, where no field is zero: the name length arrives three times in a
     * row - as a byte, as a number, and as the block in front of the letters.
     */
    @Test
    void aWideQueryComesBackWithRows() throws Exception {
        try (OracleSession session = open()) {
            java.util.concurrent.atomic.AtomicInteger seen =
                    new java.util.concurrent.atomic.AtomicInteger();
            TtcResult result = session.query("""
                    select owner, table_name, column_name, data_type, data_length,
                           data_precision, data_scale, nullable, column_id
                    from all_tab_columns where owner = 'SYS' and table_name = 'ALL_USERS'
                    """, row -> seen.incrementAndGet());
            assertEquals(9, result.columns().size(), "the description is complete");
            assertFalse(result.isFailure(), "and nothing failed");
            assertEquals(TtcResult.ORA_NO_DATA_FOUND, result.errorNumber(),
                    "1403 is how the server says the result is finished");
            assertTrue(seen.get() > 0, "the rows arrive with the description");
            assertEquals(seen.get(), result.rowCount());
        }
    }
}
