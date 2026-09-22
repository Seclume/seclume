package space.seclume.diff;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * A real session, broken part way through.
 *
 * <p>Everything else in this module asks whether the driver is right when the
 * other end behaves. This asks what it does when the other end stops - which
 * is the question an operator actually has, because networks are not reliable
 * and servers are restarted.
 *
 * <h2>The one that matters</h2>
 *
 * <p>Of everything here, one property is worth more than the rest:
 * <b>a truncated stream must never look like a finished one</b>. A driver
 * that raises an exception on a broken connection is merely correct. A driver
 * that hands back the four hundred rows it managed to read, with
 * {@code next()} answering false as though that were the end, has silently
 * lost data - and the application writes the short answer into a report, or a
 * ledger, and nobody finds out. That is the failure mode this test exists
 * for, and the reason the assertion is two-sided rather than
 * {@code assertThrows}.
 *
 * <h2>Why a proxy and not a fake server</h2>
 *
 * <p>The fuzz tests point a driver at something that never was a server.
 * Here the session is genuine - authenticated, doing real work against the
 * real thing - and the fault arrives in the middle of it. That is where "it
 * works" and "it is correct" come apart, and it needs the real server on the
 * far side to get there.
 *
 * <p>Each driver reports all of its findings together rather than stopping at
 * the first, and skips itself when its server is not there.
 */
@Timeout(600)
class FaultInjectionTest {

    /** Enough rows that a cut lands in the middle of the stream, not after it. */
    private static final int ROWS = 20_000;
    /** Few enough that a byte-at-a-time relay finishes in a sensible time. */
    private static final int SHORT_ROWS = 200;

    /**
     * One database, and the four things that differ about talking to it.
     *
     * @param longQuery  must return {@link #ROWS} rows, wide enough that the
     *                   stream is worth cutting
     * @param shortQuery the same shape, {@link #SHORT_ROWS} rows
     * @param setUp      statements to run before the transaction test, or
     *                   empty - Oracle commits its DDL and cannot make a
     *                   temporary table inside a transaction the way the
     *                   others can
     * @param insert     something that leaves the transaction with work to
     *                   commit, so the commit is a round trip and not a
     *                   no-op the driver can answer by itself
     */
    private record Target(String name, String host, int port, String passwordFile,
                          String urlTemplate, String longQuery, String shortQuery,
                          List<String> setUp, String insert, List<String> tearDown) {

        String url(int proxyPort, Path password) {
            return urlTemplate
                    .replace("{port}", Integer.toString(proxyPort))
                    .replace("{path}", password.toString().replace('\\', '/'));
        }
    }

    private static Target postgres() {
        return new Target("postgresql", TestHosts.postgres(), TestHosts.postgresPort(),
                TestHosts.postgresPasswordFile(),
                "jdbc:seclume:postgresql://127.0.0.1:{port}/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path={path}",
                "select i, repeat('x', 40) as padding "
                + "from generate_series(1, " + ROWS + ") as i",
                "select i, repeat('x', 40) as padding "
                + "from generate_series(1, " + SHORT_ROWS + ") as i",
                List.of("create temporary table fault_commit (i int)"),
                "insert into fault_commit values (1)",
                List.of());
    }

    private static Target mysql() {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        return new Target("mysql",
                System.getProperty("seclume.mysql.host", TestHosts.database()), port,
                ".local-mysql-password",
                "jdbc:seclume:mysql://127.0.0.1:{port}/seclume_test"
                + "?user=seclume_test&tls=off&allowPublicKeyRetrieval=true"
                + "&provider=file&path={path}",
                numbers(ROWS), numbers(SHORT_ROWS),
                List.of("create temporary table fault_commit (i int)"),
                "insert into fault_commit values (1)",
                List.of());
    }

    /**
     * MySQL has no {@code generate_series}, and its recursive CTE stops at a
     * thousand rows unless the session says otherwise. A cross join over the
     * digits needs neither.
     */
    private static String numbers(int rows) {
        String digits = "(select 0 n union all select 1 union all select 2 union all "
                + "select 3 union all select 4 union all select 5 union all select 6 "
                + "union all select 7 union all select 8 union all select 9)";
        // Ordered, and the order is the whole point rather than tidiness.
        // This is a cross join of a hundred thousand rows with a limit on it:
        // without an order by, which two hundred of them come back and in
        // which sequence is the server's to decide, and it does not decide
        // the same way twice. The check below compares two runs with each
        // other and called every difference a fragmentation fault - three
        // runs out of four, on a driver that was doing nothing wrong.
        return "select a.n * 10000 + b.n * 1000 + c.n * 100 + d.n * 10 + e.n as i, "
                + "repeat('x', 40) as padding from " + digits + " a, " + digits + " b, "
                + digits + " c, " + digits + " d, " + digits + " e order by i limit " + rows;
    }

    private static Target sqlServer() {
        int port = Integer.getInteger("seclume.mssql.port", 1433);
        return new Target("sqlserver",
                System.getProperty("seclume.mssql.host", TestHosts.database()), port,
                ".local-mssql-password",
                "jdbc:seclume:sqlserver://127.0.0.1:{port}/master"
                + "?user=sa&trustServerCertificate=true&provider=file&path={path}",
                topRows(ROWS), topRows(SHORT_ROWS),
                List.of("create table #fault_commit (i int)"),
                "insert into #fault_commit values (1)",
                List.of());
    }

    private static String topRows(int rows) {
        // The same reasoning as for MySQL: row_number() over (order by
        // (select null)) numbers the rows in whatever order they arrive, and
        // "top n" of an unordered cross join is not a fixed set. The outer
        // order by makes the answer the same twice; the inner one cannot,
        // because there is nothing in sys.all_objects worth ordering by.
        return "select i, padding from (select top " + rows
                + " row_number() over (order by (select null)) as i, "
                + "replicate('x', 40) as padding "
                + "from sys.all_objects a cross join sys.all_objects b) numbered "
                + "order by i";
    }

    private static Target oracle() {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        String service = System.getProperty("seclume.oracle.service", "FREEPDB1");
        String user = System.getProperty("seclume.oracle.user", "seclume_test");
        return new Target("oracle",
                System.getProperty("seclume.oracle.host", TestHosts.database()), port,
                ".local-oracle-password",
                "jdbc:seclume:oracle://127.0.0.1:{port}/" + service
                + "?user=" + user + "&provider=file&path={path}",
                connectBy(ROWS), connectBy(SHORT_ROWS),
                // DDL commits in Oracle, so the table is made before the
                // transaction starts rather than inside it.
                List.of("create table fault_commit (i number)"),
                "insert into fault_commit values (1)",
                List.of("drop table fault_commit"));
    }

    private static String connectBy(int rows) {
        return "select level as i, rpad('x', 40, 'x') as padding "
                + "from dual connect by level <= " + rows;
    }

    // ------------------------------------------------------------- the runs --

    @Test
    void postgresSurvivesABrokenConnection() throws Exception {
        battery(postgres());
    }

    @Test
    void mysqlSurvivesABrokenConnection() throws Exception {
        battery(mysql());
    }

    @Test
    void sqlServerSurvivesABrokenConnection() throws Exception {
        battery(sqlServer());
    }

    @Test
    void oracleSurvivesABrokenConnection() throws Exception {
        battery(oracle());
    }

    // ------------------------------------------------------------- the tests --

    private void battery(Target target) throws Exception {
        Path password = locate(target.passwordFile());
        Assumptions.assumeTrue(password != null, "no " + target.passwordFile());
        Assumptions.assumeTrue(reachable(target), "no " + target.name() + " on "
                + target.host() + ":" + target.port());

        List<String> findings = new ArrayList<>();
        check(findings, "the proxy itself changes nothing", () -> proxyChangesNothing(target,
                password));
        check(findings, "a fragmented stream gives the same answer",
                () -> fragmentedMatches(target, password));
        check(findings, "a cut mid-query is not a short answer",
                () -> cutIsNotSilent(target, password));
        check(findings, "a cut connection does not claim to be valid",
                () -> cutIsNotValid(target, password));
        check(findings, "a cut during commit is not success",
                () -> cutCommitFails(target, password));

        if (!findings.isEmpty()) {
            throw new AssertionError(target.name() + " answered " + findings.size()
                    + " fault(s) wrongly:\n  " + String.join("\n  ", findings));
        }
    }

    @FunctionalInterface
    private interface Check {
        void run() throws Exception;
    }

    private static void check(List<String> findings, String what, Check check) {
        try {
            check.run();
        } catch (AssertionError wrong) {
            findings.add(what + ": " + wrong.getMessage());
        } catch (Exception broke) {
            findings.add(what + ": threw " + broke.getClass().getName() + ": "
                    + broke.getMessage());
        }
    }

    /** Without this, the rest would prove only that a proxy can break things. */
    private void proxyChangesNothing(Target target, Path password) throws Exception {
        try (FaultProxy proxy = proxy(target, FaultProxy.Mode.PASS);
             Connection connection = DriverManager.getConnection(target.url(proxy.port(),
                     password));
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(target.longQuery())) {

            int seen = 0;
            while (rows.next()) {
                seen++;
            }
            if (seen != ROWS) {
                throw new AssertionError("expected " + ROWS + " rows, got " + seen);
            }
        }
    }

    /**
     * One byte per write, and the answer has to be identical.
     *
     * <p>A reassembler that works only because the operating system usually
     * hands over a whole message at once fails here - and in production under
     * load, or behind any proxy, where it gets blamed on the network.
     */
    private void fragmentedMatches(Target target, Path password) throws Exception {
        List<String> direct = readDirect(target, password);
        try (FaultProxy proxy = proxy(target, FaultProxy.Mode.FRAGMENT);
             Connection connection = DriverManager.getConnection(target.url(proxy.port(),
                     password));
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(target.shortQuery())) {

            List<String> fragmented = read(rows);
            if (!direct.equals(fragmented)) {
                throw new AssertionError("the same query gave a different answer when the "
                        + "bytes arrived one at a time: " + difference(direct, fragmented));
            }
        }
    }

    /**
     * Where two answers part company, in enough detail to act on.
     *
     * <p>The message this replaces printed the two row counts, which are
     * equal whenever the difference is in a value rather than in a length -
     * and that is the interesting half. A finding nobody can act on is worse
     * than none: it gets looked at once, filed as flaky, and then the real
     * one is filed the same way.
     */
    private static String difference(List<String> direct, List<String> fragmented) {
        if (direct.size() != fragmented.size()) {
            return direct.size() + " rows direct, " + fragmented.size() + " fragmented";
        }
        for (int i = 0; i < direct.size(); i++) {
            if (!direct.get(i).equals(fragmented.get(i))) {
                return "same length (" + direct.size() + " rows), first difference at row "
                        + (i + 1) + ": direct \"" + direct.get(i) + "\", fragmented \""
                        + fragmented.get(i) + "\"";
            }
        }
        return "equal element by element, so the lists differ in a way this cannot show";
    }

    /**
     * The important one: a truncated stream must not read as a finished one.
     *
     * <p>It only means anything when the rows are actually streamed. With the
     * default settings all four drivers read the whole result before
     * {@code executeQuery} returns, so a cut lands there and the exception
     * arrives before the application has seen a single row - safe, but it
     * proves nothing about what was being asked. The first version of this
     * test passed on all four for exactly that reason, which is why it now
     * insists that some rows arrived first.
     *
     * <p>So: a fetch size, and a transaction to hold the cursor open. That is
     * also the configuration in which the question matters - an application
     * that streams a large result is the one that could be handed a short
     * answer and believe it.
     */
    private void cutIsNotSilent(Target target, Path password) throws Exception {
        try (FaultProxy proxy = proxy(target, FaultProxy.Mode.CUT)) {
            proxy.cutAfterServerBytes(64 * 1024);

            try (Connection connection = DriverManager.getConnection(target.url(proxy.port(),
                    password))) {

                connection.setAutoCommit(false);
                // A prepared statement, because that is what streams. On
                // PostgreSQL a fetch size only takes effect in the extended
                // protocol - seclume says so in PgStatement and means it -
                // and a plain Statement therefore reads the whole result
                // before returning. Measured, not assumed: see
                // FetchSizeProbe, which also shows pgjdbc doing it the other
                // way. Using a Statement here would have made this test
                // prove nothing, which it quietly did until the assertion
                // below was added.
                try (java.sql.PreparedStatement statement =
                        connection.prepareStatement(target.longQuery())) {
                statement.setFetchSize(50);

                int seen = 0;
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        seen++;
                    }
                    throw new AssertionError("the result ended after " + seen + " of " + ROWS
                            + " rows with no exception - a truncated stream was reported as a "
                            + "complete one");
                } catch (SQLException expected) {
                    if (seen >= ROWS) {
                        throw new AssertionError("the cut came after the last row and proved "
                                + "nothing; lower the byte budget");
                    }
                    // And it has to have landed in the middle. Without this
                    // the test would pass on a driver that failed before the
                    // first row ever arrived - an exception for some other
                    // reason, which is not what is being checked here.
                    if (seen == 0) {
                        throw new AssertionError("the query failed before a single row "
                                + "arrived, so nothing was truncated and nothing was "
                                + "proved; raise the byte budget (relayed "
                                + proxy.relayedFromServer() + " bytes, error: "
                                + expected.getMessage() + ")");
                    }
                }
                }
            }
        }
    }

    /** A connection that calls itself valid after its socket died gets reused. */
    private void cutIsNotValid(Target target, Path password) throws Exception {
        try (FaultProxy proxy = proxy(target, FaultProxy.Mode.CUT);
             Connection connection = DriverManager.getConnection(target.url(proxy.port(),
                     password))) {

            if (!connection.isValid(3)) {
                throw new AssertionError("it was not valid even before the cut");
            }
            proxy.cutNow();
            if (connection.isValid(3)) {
                throw new AssertionError("it called itself valid after its socket was reset");
            }
            try (Statement statement = connection.createStatement()) {
                statement.executeQuery("select 1" + (target.name().equals("oracle")
                        ? " from dual" : "")).close();
                throw new AssertionError("a query succeeded on a dead connection");
            } catch (SQLException expected) {
                // What should happen.
            }
        }
    }

    /**
     * A cut while committing is never reported as success.
     *
     * <p>The one case where a wrong answer costs money. Whether the server
     * committed is genuinely unknown after this - that is the nature of the
     * failure - and the only honest thing a driver can do is say so.
     */
    private void cutCommitFails(Target target, Path password) throws Exception {
        try (FaultProxy proxy = proxy(target, FaultProxy.Mode.CUT);
             Connection connection = DriverManager.getConnection(target.url(proxy.port(),
                     password))) {

            try (Statement statement = connection.createStatement()) {
                for (String sql : target.setUp()) {
                    statement.execute(sql);
                }
            }
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute(target.insert());
            }
            proxy.cutNow();

            try {
                connection.commit();
                throw new AssertionError("commit returned normally on a connection whose "
                        + "socket had gone");
            } catch (SQLException expected) {
                // What should happen.
            }
        } finally {
            cleanUp(target, password);
        }
    }

    /** Oracle's table outlives the transaction, so it is dropped on the way out. */
    private void cleanUp(Target target, Path password) {
        if (target.tearDown().isEmpty()) {
            return;
        }
        try (FaultProxy proxy = proxy(target, FaultProxy.Mode.PASS);
             Connection connection = DriverManager.getConnection(target.url(proxy.port(),
                     password));
             Statement statement = connection.createStatement()) {
            for (String sql : target.tearDown()) {
                statement.execute(sql);
            }
        } catch (Exception alreadyGone) {
            // The table may never have been made; nothing to report.
        }
    }

    // ------------------------------------------------------------ fixtures --

    private static FaultProxy proxy(Target target, FaultProxy.Mode mode) throws IOException {
        return new FaultProxy(target.host(), target.port(), mode);
    }

    private static List<String> readDirect(Target target, Path password) throws SQLException {
        String url = target.url(target.port(), password)
                .replace("//127.0.0.1:", "//" + target.host() + ":");
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(target.shortQuery())) {
            return read(rows);
        }
    }

    private static List<String> read(ResultSet rows) throws SQLException {
        List<String> values = new ArrayList<>();
        while (rows.next()) {
            values.add(rows.getString(1) + ":" + rows.getString(2));
        }
        return values;
    }

    private static Path locate(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static boolean reachable(Target target) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(target.host(), target.port()), 2000);
            return true;
        } catch (IOException unreachable) {
            return false;
        }
    }
}
