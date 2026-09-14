package space.seclume.internal.jdbc;

import java.sql.SQLException;

/**
 * An upper bound for a result, so that a forgotten {@code where} ends in an
 * error instead of an {@code OutOfMemoryError}.
 *
 * <p>Every driver reads the rows of a statement into memory before handing
 * them out, and every driver in the world happily reads until the heap is
 * gone. What is left afterwards is a process that took the whole application
 * with it and a stack trace that names the allocation, not the query.
 *
 * <p>{@code setMaxRows} exists and does not help: one row with a large
 * {@code text} column is enough. The size in bytes is what actually decides
 * whether the heap survives, and the driver is the only place that knows it -
 * it owns the buffer.
 *
 * <p>Off by default. Nothing here costs anything when it is off: the check is
 * one comparison per row against a field that is {@code 0}.
 */
public final class ResultLimit {

    /** No bound - what every connection has unless it is configured. */
    public static final ResultLimit NONE = new ResultLimit(0, 0);

    private final long maxBytes;
    private final long maxRows;

    private ResultLimit(long maxBytes, long maxRows) {
        this.maxBytes = maxBytes;
        this.maxRows = maxRows;
    }

    /**
     * @param maxBytes how many bytes of row data a single result may hold,
     *                 0 for no bound
     * @param maxRows  how many rows, 0 for no bound - {@code setMaxRows} cuts
     *                 the result off silently, this one says something
     */
    public static ResultLimit of(long maxBytes, long maxRows) {
        if (maxBytes < 0 || maxRows < 0) {
            throw new IllegalArgumentException("a result limit cannot be negative");
        }
        return maxBytes == 0 && maxRows == 0 ? NONE : new ResultLimit(maxBytes, maxRows);
    }

    /** Whether anything is bounded at all - lets a caller skip the counting. */
    public boolean isSet() {
        return this != NONE;
    }

    public long maxBytes() {
        return maxBytes;
    }

    public long maxRows() {
        return maxRows;
    }

    /**
     * Checked once per row while the result is being read.
     *
     * <p>The message names the query and the size reached, because those are
     * the two things somebody woken at night needs and neither is in an
     * {@code OutOfMemoryError}.
     *
     * @param sql the statement, for the message - never any value from it
     */
    public void check(long bytes, long rows, String sql) throws SQLException {
        if (maxBytes > 0 && bytes > maxBytes) {
            throw new SQLException("this result is larger than the configured limit: "
                    + bytes + " bytes of row data, at most " + maxBytes
                    + " allowed (maxResultBytes) - the statement was: " + shorten(sql)
                    + ". Narrow the query, or raise the limit if the result really is "
                    + "meant to be this big.", "54001");
        }
        if (maxRows > 0 && rows > maxRows) {
            throw new SQLException("this result has more rows than the configured limit: "
                    + rows + ", at most " + maxRows
                    + " allowed (maxResultRows) - the statement was: " + shorten(sql)
                    + ". Narrow the query, or raise the limit if the result really is "
                    + "meant to be this long.", "54001");
        }
    }

    /**
     * A long statement is cut short: an error message with four kilobytes of
     * generated SQL in it is not read, it is scrolled past. And a statement
     * with values written into it would carry them into the log - which is why
     * only the beginning goes in.
     */
    private static String shorten(String sql) {
        if (sql == null) {
            return "(unknown)";
        }
        String text = sql.strip();
        return text.length() <= 120 ? text : text.substring(0, 117) + "...";
    }

    @Override
    public String toString() {
        if (!isSet()) {
            return "no result limit";
        }
        return "at most " + (maxBytes > 0 ? maxBytes + " bytes" : "any size")
                + " and " + (maxRows > 0 ? maxRows + " rows" : "any number of rows");
    }
}
