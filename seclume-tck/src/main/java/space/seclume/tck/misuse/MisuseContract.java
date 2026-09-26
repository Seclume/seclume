package space.seclume.tck.misuse;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * What a driver must do when the <b>caller</b> is the one sending nonsense.
 *
 * <p>The fuzz sweeps ask what happens when the server is wrong. This asks the
 * other half of the same question, and it is the half that happens in
 * production every day: an application reads a column before calling
 * {@code next()}, commits when there is no transaction, uses a result set
 * whose statement somebody else closed. None of that is exotic - it is what
 * ordinary code does when two threads, a framework and a connection pool are
 * in the room together.
 *
 * <p><b>Why this needs saying at all.</b> Four protocols written from scratch
 * means four state machines, and each one was built by driving it correctly.
 * A driver that has only ever been asked for things in the right order has a
 * wrong order that nobody has tried - and the cost of getting it wrong is not
 * an exception, it is a <b>desynchronised stream</b>: a request written for a
 * state the connection is not in, an answer the decoder reads as something
 * else, and a session that keeps working while returning the wrong rows. The
 * failure surfaces three calls later, in code that did nothing wrong.
 *
 * <h2>What is required</h2>
 *
 * <ol>
 *   <li><b>A refusal is a {@link SQLException}.</b> Not an
 *       {@code IllegalStateException}, not an
 *       {@code ArrayIndexOutOfBoundsException}, not a
 *       {@code NullPointerException}. The caller's {@code catch} is written
 *       against the JDBC signature, and anything else goes past it.
 *   <li><b>What the specification says must be accepted is accepted.</b>
 *       Closing twice, cancelling when nothing is running - these are the
 *       calls a {@code finally} block and a timeout thread make, and a driver
 *       that throws on them turns a clean shutdown into a stack trace.
 *   <li><b>The connection survives it.</b> This is the one that matters. A
 *       misuse is a mistake in the caller, not a reason to lose a pooled
 *       connection - and more to the point, a driver that writes a request it
 *       should have refused has put a byte on the wire that the next answer
 *       will be read against. So after every case the connection is asked for
 *       a row, and it has to produce one.
 * </ol>
 *
 * <p>Every case says for itself which of the three apply, because some of them
 * deliberately close the connection they are given.
 */
public final class MisuseContract {

    /** Where a fresh connection comes from - one per case, because some end badly. */
    public interface Connections {
        Connection open() throws SQLException;
    }

    /** What the driver is asked to do out of order. */
    public interface Misuse {
        void run(Connection connection) throws Exception;
    }

    /** Whether the call is one JDBC refuses or one it has to accept. */
    public enum Expected {
        /** A {@link SQLException} is required; anything else, including success, is a breach. */
        REFUSED,
        /** Completing without throwing is required. */
        ACCEPTED,
        /**
         * Completing, or saying plainly that the driver does not do this.
         *
         * <p>For the calls JDBC lets a driver decline with a
         * {@link java.sql.SQLFeatureNotSupportedException}. Declining is an
         * answer a caller can act on - it is in the signature and it names
         * itself - and it is not the same as failing. What this still rules
         * out is every other way of going wrong, and it still requires the
         * connection to work afterwards.
         */
        ACCEPTED_OR_DECLINED
    }

    /**
     * One thing done in the wrong order.
     *
     * @param usableAfterwards whether the connection must still answer a query
     *                         when this is over; false only where the case
     *                         closed it on purpose
     */
    public record Case(String name, Expected expected, boolean usableAfterwards, Misuse body) {

        public Case(String name, Expected expected, Misuse body) {
            this(name, expected, true, body);
        }
    }

    private MisuseContract() {
    }

    /**
     * Runs every case and reports the ones that broke the contract.
     *
     * @param label      which driver, for the report
     * @param selectOne  a query returning one row of one column; the dialects
     *                   differ only in whether a {@code from} is compulsory
     * @throws AssertionError if anything broke the contract
     */
    public static void check(String label, Connections connections, String selectOne,
                             List<Case> cases) {
        Map<String, String> breaches = new TreeMap<>();
        Map<String, Integer> tally = new TreeMap<>();

        for (Case one : cases) {
            Connection connection;
            try {
                connection = connections.open();
            } catch (SQLException unreachable) {
                throw new AssertionError("could not open a connection for '" + one.name()
                        + "': " + unreachable.getMessage(), unreachable);
            }
            try {
                String breach = runOne(one, connection, selectOne);
                if (breach == null) {
                    tally.merge(one.expected().name().toLowerCase(java.util.Locale.ROOT),
                            1, Integer::sum);
                } else {
                    breaches.put(one.name(), breach);
                }
            } finally {
                try {
                    connection.close();
                } catch (SQLException ignored) {
                    // A case that wrecked the connection is already a finding;
                    // failing to close it afterwards adds nothing.
                }
            }
        }

        System.err.println("[misuse " + label + "] " + cases.size() + " cases, " + tally);

        if (!breaches.isEmpty()) {
            StringBuilder report = new StringBuilder(breaches.size() + " of " + cases.size()
                    + " calls broke the contract (" + label + "):\n");
            breaches.forEach((name, why) ->
                    report.append("\n== ").append(name).append('\n').append(why).append('\n'));
            throw new AssertionError(report.toString());
        }
    }

    /** @return null when the case held, otherwise what went wrong */
    private static String runOne(Case one, Connection connection, String selectOne) {
        try {
            one.body().run(connection);
            if (one.expected() == Expected.REFUSED) {
                return "the driver accepted it. JDBC requires a SQLException here, and a "
                        + "caller that gets none carries on believing the call worked";
            }
        } catch (SQLException refused) {
            // A refusal is a SQLException, and so is a declining - the second
            // is a subclass of the first, which is why this is one clause and
            // not two: a case that requires a refusal is satisfied by either.
            boolean declined = refused instanceof java.sql.SQLFeatureNotSupportedException;
            if (one.expected() == Expected.ACCEPTED
                    || (one.expected() == Expected.ACCEPTED_OR_DECLINED && !declined)) {
                return "refused with " + refused.getClass().getSimpleName() + " ("
                        + refused.getSQLState() + "): " + refused.getMessage()
                        + " - this is a call the specification requires to work, and a "
                        + "finally block cannot be written around a close that throws";
            }
        } catch (Throwable thrown) {
            return "threw " + thrown.getClass().getName() + ": " + thrown.getMessage()
                    + " - not a SQLException, so the caller's catch does not see it";
        }

        if (!one.usableAfterwards()) {
            return null;
        }
        try (java.sql.Statement statement = connection.createStatement();
             java.sql.ResultSet rows = statement.executeQuery(selectOne)) {
            if (!rows.next()) {
                return "the connection answered no rows afterwards - the session is no longer "
                        + "in the state the driver believes it is in";
            }
            rows.getObject(1);
        } catch (Throwable afterwards) {
            return "the connection was unusable afterwards: "
                    + afterwards.getClass().getSimpleName() + ": " + afterwards.getMessage()
                    + " - a mistake in the caller must not cost a pooled connection, and a "
                    + "request written in the wrong state leaves the stream out of step";
        }
        return null;
    }

    // ---- the cases every driver gets --------------------------------------

    /**
     * The standard list, in the order of the JDBC objects it misuses.
     *
     * @param selectOne     one row, one column
     * @param selectTwoRows two rows, one column - for the cursor cases
     * @param selectWithAParameter the same with one placeholder left unset;
     *                      handed in rather than derived, because the four
     *                      dialects disagree about both the placeholder and
     *                      whether a {@code where} may stand without a
     *                      {@code from}
     */
    public static List<Case> standard(String selectOne, String selectTwoRows,
                                      String selectWithAParameter) {
        List<Case> cases = new ArrayList<>();

        // ---- the result set, before and after the rows ----
        cases.add(new Case("a value before the first row", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement();
                 java.sql.ResultSet rows = statement.executeQuery(selectOne)) {
                rows.getObject(1);
            }
        }));
        cases.add(new Case("a value after the last row", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement();
                 java.sql.ResultSet rows = statement.executeQuery(selectOne)) {
                while (rows.next()) {
                    rows.getObject(1);
                }
                rows.getObject(1);
            }
        }));
        cases.add(new Case("column zero", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement();
                 java.sql.ResultSet rows = statement.executeQuery(selectOne)) {
                rows.next();
                rows.getObject(0);
            }
        }));
        cases.add(new Case("a column past the last one", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement();
                 java.sql.ResultSet rows = statement.executeQuery(selectOne)) {
                rows.next();
                rows.getObject(99);
            }
        }));
        cases.add(new Case("a column name that is not there", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement();
                 java.sql.ResultSet rows = statement.executeQuery(selectOne)) {
                rows.next();
                rows.getObject("no_such_column");
            }
        }));
        cases.add(new Case("a result set whose statement was closed",
                Expected.REFUSED, connection -> {
            java.sql.Statement statement = connection.createStatement();
            java.sql.ResultSet rows = statement.executeQuery(selectTwoRows);
            statement.close();
            rows.next();
            rows.getObject(1);
        }));
        cases.add(new Case("a result set left behind by a second query",
                Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                java.sql.ResultSet first = statement.executeQuery(selectTwoRows);
                // The specification closes this one implicitly. A driver that
                // leaves it open leaves two cursors reading one stream.
                statement.executeQuery(selectTwoRows);
                first.next();
                first.getObject(1);
            }
        }));
        cases.add(new Case("a row left half-read, and then the next query",
                Expected.ACCEPTED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                java.sql.ResultSet rows = statement.executeQuery(selectTwoRows);
                rows.next();
                // Abandoned with rows still on the wire: the driver has to
                // drain them, or the next answer starts inside this one.
                rows.close();
            }
        }));

        // ---- the statement ----
        cases.add(new Case("a query on a closed statement", Expected.REFUSED, connection -> {
            java.sql.Statement statement = connection.createStatement();
            statement.close();
            statement.executeQuery(selectOne);
        }));
        cases.add(new Case("executeUpdate with a select", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                statement.executeUpdate(selectOne);
            }
        }));
        cases.add(new Case("a negative query timeout", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(-1);
            }
        }));
        cases.add(new Case("a negative fetch size", Expected.REFUSED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                statement.setFetchSize(-1);
            }
        }));
        cases.add(new Case("closing a statement twice", Expected.ACCEPTED, connection -> {
            java.sql.Statement statement = connection.createStatement();
            statement.close();
            statement.close();
        }));
        cases.add(new Case("more results before anything ran", Expected.ACCEPTED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                statement.getMoreResults();
            }
        }));

        // ---- cancellation, which arrives from another thread by definition ----
        cases.add(new Case("cancel with nothing running", Expected.ACCEPTED_OR_DECLINED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                statement.cancel();
            }
        }));
        cases.add(new Case("cancel after the answer was read", Expected.ACCEPTED_OR_DECLINED, connection -> {
            try (java.sql.Statement statement = connection.createStatement()) {
                try (java.sql.ResultSet rows = statement.executeQuery(selectOne)) {
                    while (rows.next()) {
                        rows.getObject(1);
                    }
                }
                // The race a query timeout loses: the cancel arrives after the
                // call it meant to stop is over. Whatever it puts on the wire
                // has to be something the next call can read past.
                statement.cancel();
            }
        }));
        cases.add(new Case("cancel on a closed statement", Expected.REFUSED, connection -> {
            java.sql.Statement statement = connection.createStatement();
            statement.close();
            statement.cancel();
        }));

        // ---- the prepared statement ----
        cases.add(new Case("a prepared statement with a parameter missing",
                Expected.REFUSED, connection -> {
            try (java.sql.PreparedStatement statement =
                         connection.prepareStatement(selectWithAParameter)) {
                statement.executeQuery();
            }
        }));
        cases.add(new Case("a parameter at index zero", Expected.REFUSED, connection -> {
            try (java.sql.PreparedStatement statement = connection.prepareStatement(selectOne)) {
                statement.setInt(0, 1);
            }
        }));

        // ---- the connection and its transaction ----
        cases.add(new Case("commit outside a transaction", Expected.REFUSED,
                Connection::commit));
        cases.add(new Case("rollback outside a transaction", Expected.REFUSED,
                Connection::rollback));
        cases.add(new Case("a savepoint in auto-commit", Expected.REFUSED, connection ->
                connection.setSavepoint("nowhere")));
        cases.add(new Case("an isolation level that does not exist",
                Expected.REFUSED, connection ->
                connection.setTransactionIsolation(999)));
        cases.add(new Case("isValid with a negative timeout", Expected.REFUSED, connection ->
                connection.isValid(-1)));
        cases.add(new Case("unwrap to something unrelated", Expected.REFUSED, connection ->
                connection.unwrap(String.class)));
        cases.add(new Case("a statement on a closed connection",
                Expected.REFUSED, false, connection -> {
            connection.close();
            connection.createStatement();
        }));
        cases.add(new Case("closing a connection twice", Expected.ACCEPTED, false, connection -> {
            connection.close();
            connection.close();
        }));

        return cases;
    }
}
