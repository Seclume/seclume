package space.seclume.postgresql.jdbc;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLXML;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import space.seclume.internal.jdbc.StreamValues;
import space.seclume.postgresql.PgParameters;
import space.seclume.postgresql.PgSession;

/**
 * A prepared statement in the extended protocol.
 *
 * <p>{@code Parse} runs once, {@code Bind}/{@code Execute} on every execution.
 * The server keeps the plan for as long as the statement is open.
 *
 * <p>Parameters go over the wire as parameters, never as text inside the SQL.
 * With that there is no SQL injection here - not because something gets
 * escaped, but because values and statement are separate fields of the same
 * message.
 */
/*
 * Not final: PgCallableStatement is the same statement with a call in front of
 * it and output parameters behind it, and everything in between - parse, bind,
 * execute, the plan cache - is this class's and should stay in one place.
 */
class PgPreparedStatement extends PgStatement
        implements PreparedStatement, space.seclume.SensitiveParameters {

    private String sql;
    /** As the caller wrote it. */
    private final String originalSql;
    /**
     * The text of the plan this statement holds, in the caller's spelling -
     * the key the connection caches it under. The caller's text, or its form
     * for the lists bound to {@code in (?)}.
     */
    private String planSql;
    /** Lists bound to {@code in (?)}, by parameter index - see InLists; null for none. */
    private space.seclume.internal.jdbc.InLists.Bound[] lists;
    private String name;
    private final PgParameters parameters;
    private final int expectedParameters;
    private List<PgSession.Field> described;
    private List<Object[]> batch;
    private boolean prepared;
    private boolean released;

    /**
     * @param cached what the server already said about this plan, when the
     *               connection handed back one it had parsed before - null for
     *               a plan that does not exist on the server yet
     */
    PgPreparedStatement(PgConnection connection, String sql, String name,
            List<PgSession.Field> cached) throws SQLException {
        super(connection);
        // PostgreSQL knows no question marks; $1, $2 ... are its placeholders.
        PgSqlRewriter.Rewritten rewritten = PgSqlRewriter.rewrite(sql);
        this.originalSql = sql;
        this.planSql = sql;
        this.sql = rewritten.sql();
        this.expectedParameters = rewritten.parameters();
        this.name = name;
        this.parameters = new PgParameters(Math.max(rewritten.parameters(), 8));
        if (cached != null) {
            // The plan is on the server and its shape is known. Nothing has to
            // be announced and nothing has to be described - the first Bind can
            // go straight out.
            this.described = cached;
            this.prepared = true;
        }
    }

    /**
     * Announces the plan; the server parses it with the first execution.
     *
     * <p>A {@code Parse} of its own would be a round trip whose answer nobody
     * needs yet - sent together with the first {@code Bind} and
     * {@code Execute}, it costs nothing. Whoever asks for the column
     * description before running the statement gets it, and pays the round
     * trip then; see {@link #getMetaData()}.
     */
    private void prepare() throws SQLException {
        followLists();
        if (!prepared) {
            connection.session().parseLater(name, sql);
            prepared = true;
        }
    }

    /**
     * Switches to the plan for the lists now bound, when that is another text
     * than the plan held - {@code = any(cast(? as bigint[]))} where the caller
     * wrote {@code in (?)}. The plan held goes back to the connection's cache
     * under its own text, so switching back and forth parses nothing twice.
     */
    private void followLists() throws SQLException {
        String wanted = space.seclume.internal.jdbc.InLists.apply(originalSql, lists,
                space.seclume.internal.jdbc.InLists.Dialect.POSTGRESQL);
        if (wanted.equals(planSql)) {
            return;
        }
        if (prepared) {
            connection.releasePlan(planSql, name, described);
        }
        planSql = wanted;
        sql = PgSqlRewriter.rewrite(wanted).sql();
        name = connection.newStatementName();
        prepared = false;
        described = null;
    }

    /** Forces the announced plan to be parsed now, because somebody asks. */
    private void describeNow() throws SQLException {
        prepare();
        if (described == null && connection.session().hasPendingParse(name)) {
            described = connection.session().parse(name, sql);
        }
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        runPrepared();
        if (wantsGeneratedKeys()) {
            // The rows of the rewritten statement are the keys, and JDBC says
            // what execute() reports then: false, and the count through
            // getUpdateCount. It reported true and -1, so MyBatis - which
            // calls execute() and reads the count - saw an insert that had
            // changed nothing. executeUpdate() already did this. Found by the
            // frameworks suite.
            keepAsGeneratedKeys();
            return false;
        }
        return currentResultSet() != null;
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        runPrepared();
        ResultSet result = currentResultSet();
        if (result == null) {
            throw new SQLException("the statement returned no rows: " + shape(sql)
                    + " - use executeUpdate for statements that do not select");
        }
        return result;
    }

    @Override
    public int executeUpdate() throws SQLException {
        return (int) Math.min(executeLargeUpdate(), Integer.MAX_VALUE);
    }

    @Override
    public long executeLargeUpdate() throws SQLException {
        checkOpen();
        PgSession session = connection.session();
        if (session.isPipelining()) {
            // Inside a pipeline block: written now, sent later. The answer is
            // SUCCESS_NO_INFO because the count really is not known yet - see
            // space.seclume.Pipeline.
            return buffered(session);
        }
        runPrepared();
        if (wantsGeneratedKeys()) {
            // The rewritten statement answered with rows; they are the keys,
            // not a result the caller iterates.
            keepAsGeneratedKeys();
        }
        return Math.max(updateCountValue(), 0);
    }

    /** One execution into the block, without waiting for its count. */
    private long buffered(PgSession session) throws SQLException {
        prepare();
        if (parameters.count() < expectedParameters) {
            throw new SQLException("the statement has " + expectedParameters
                    + " parameters but only " + parameters.count() + " were set");
        }
        return session.pipelineBindAndExecute(name, parameters, sql);
    }

    private void runPrepared() throws SQLException {
        underDeadline(sql, this::runPreparedNow);
    }

    private void runPreparedNow() throws SQLException {
        checkOpen();
        prepare();
        if (parameters.count() < expectedParameters) {
            throw new SQLException("the statement has " + expectedParameters
                    + " parameters but only " + parameters.count() + " were set");
        }
        PgSession session = connection.session();
        decideStreaming(true);
        // The first execution asks the server what the result looks like; every
        // one after it already knows. That saves a DESCRIBE message, the whole
        // row description coming back, and rebuilding the Field objects and
        // column names from it - measured at some five hundred bytes per
        // execution on a one-row query.
        try {
            beginExecution(session, parameters, name, executeLimit(), sql, described);
        } catch (SQLException e) {
            if (described == null || !"0A000".equals(e.getSQLState())) {
                throw e;
            }
            // "cached plan must not change result type": the table under the
            // plan changed - dropped and re-created, a column added - since it
            // was parsed, and the server will not run it in the old shape. The
            // plan is useless from now on, on this statement and in the
            // connection's cache, so it goes and a new one takes its name.
            // Outside a transaction nothing was spoilt and the statement runs
            // again at once, as pgjdbc does with autosave; inside one the
            // transaction is aborted and only its owner can decide, so the
            // error goes out - and the retry after the rollback parses afresh.
            session.closeStatementLater(name);
            name = connection.newStatementName();
            described = null;
            prepared = false;
            if (!connection.getAutoCommit()) {
                throw e;
            }
            prepare();
            beginExecution(session, parameters, name, executeLimit(), sql, null);
        }
        if (described == null) {
            // Empty counts as known: a statement that returns no rows has no
            // description, and there is no point asking again for that either.
            described = session.fields();
        }
    }

    // ---- batches ---------------------------------------------------------

    @Override
    public void addBatch() throws SQLException {
        checkOpen();
        space.seclume.internal.jdbc.InLists.refuseInBatch(lists);
        if (batch == null) {
            batch = new ArrayList<>();
        }
        Object[] snapshot = new Object[parameters.count()];
        for (int i = 0; i < snapshot.length; i++) {
            snapshot[i] = parameters.get(i + 1);
        }
        batch.add(snapshot);
    }

    @Override
    public void clearBatch() throws SQLException {
        checkOpen();
        batch = null;
        super.clearBatch();
    }

    @Override
    public long[] executeLargeBatch() throws SQLException {
        checkOpen();
        if (batch == null || batch.isEmpty()) {
            return super.executeLargeBatch();
        }
        prepare();
        closeResult();
        List<Object[]> rows = batch;
        batch = null;
        // Pipelined, not one round trip per row: the whole point of a batch.
        // Sent row by row, five hundred inserts cost five hundred times the
        // latency of the network while the database waits - measured at fifty
        // times the pipelined path on a loopback connection, and the gap grows
        // with every millisecond of distance to the server.
        // A batch in auto-commit mode commits as it goes, so a lost answer
        // here is a lost commit - see inDoubt.
        long[] counts;
        try {
            counts = connection.session().bindAndExecuteBatch(name, parameters,
                    rows.size(), index -> {
                        Object[] values = rows.get(index);
                        parameters.clear();
                        for (int p = 0; p < values.length; p++) {
                            parameters.set(p + 1, values[p]);
                        }
                    });
        } catch (SQLException failure) {
            throw inDoubt(failure, null);
        }
        for (int i = 0; i < counts.length; i++) {
            counts[i] = Math.max(counts[i], 0);
        }
        return counts;
    }

    @Override
    public void addBatch(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use addBatch() without SQL");
    }

    @Override
    public boolean execute(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use execute() without SQL");
    }

    @Override
    public ResultSet executeQuery(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use executeQuery() without SQL");
    }

    @Override
    public int executeUpdate(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use executeUpdate() without SQL");
    }

    // ---- parameters ------------------------------------------------------

    @Override
    public void clearParameters() throws SQLException {
        checkOpen();
        parameters.clear();
        lists = null;
    }

    @Override
    public void setNull(int index, int sqlType) throws SQLException {
        set(index, null);
    }

    @Override
    public void setNull(int index, int sqlType, String typeName) throws SQLException {
        set(index, null);
    }

    @Override
    public void setBoolean(int index, boolean value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setByte(int index, byte value) throws SQLException {
        set(index, (short) value);
    }

    @Override
    public void setShort(int index, short value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setInt(int index, int value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setLong(int index, long value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setFloat(int index, float value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setDouble(int index, double value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setBigDecimal(int index, BigDecimal value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setString(int index, String value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setBytes(int index, byte[] value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setDate(int index, Date value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setTime(int index, Time value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setTimestamp(int index, Timestamp value) throws SQLException {
        set(index, value);
    }

    /**
     * The three with a calendar: the value is shifted into that zone rather
     * than the calendar being refused.
     *
     * <p>This class writes out the setters itself instead of inheriting
     * {@code ParameterSetters}, so the rule lives in two places - and it is
     * the same rule, with the same reason: a calendar in UTC is how
     * Hibernate writes an {@code Instant}, and refusing it made such an
     * entity unsaveable.
     */
    @Override
    public void setDate(int index, Date value, Calendar calendar) throws SQLException {
        if (value == null || isDefaultCalendar(calendar)) {
            set(index, value);
            return;
        }
        set(index, java.time.LocalDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(value.getTime()),
                calendar.getTimeZone().toZoneId()).toLocalDate());
    }

    @Override
    public void setTime(int index, Time value, Calendar calendar) throws SQLException {
        if (value == null || isDefaultCalendar(calendar)) {
            set(index, value);
            return;
        }
        set(index, java.time.LocalDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(value.getTime()),
                calendar.getTimeZone().toZoneId()).toLocalTime());
    }

    /**
     * With the offset written out, not as bare fields.
     *
     * <p>PostgreSQL reads a value without a zone into a
     * {@code timestamptz} column <b>in the session's time zone</b>, so
     * sending the UTC fields of an {@code Instant} without saying they are
     * UTC moves the value by the machine's offset - a point in time written
     * at 09:29Z came back as 07:29Z on a machine two hours ahead. With the
     * offset there is nothing to guess; a column without a zone takes the
     * fields and drops it, which is what the calendar asked for anyway.
     */
    @Override
    public void setTimestamp(int index, Timestamp value, Calendar calendar) throws SQLException {
        if (value == null || isDefaultCalendar(calendar)) {
            set(index, value);
            return;
        }
        set(index, value.toInstant().atZone(calendar.getTimeZone().toZoneId())
                .toOffsetDateTime());
    }

    @Override
    public void setObject(int index, Object value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setObject(int index, Object value, int targetSqlType) throws SQLException {
        set(index, value);
    }

    @Override
    public void setObject(int index, Object value, int targetSqlType, int scale) throws SQLException {
        set(index, value);
    }

    /** JDBC 4.2's form with a {@code JDBCType}; the interface's default refuses it. */
    @Override
    public void setObject(int index, Object value, java.sql.SQLType targetSqlType)
            throws SQLException {
        setObject(index, value, space.seclume.internal.jdbc.ParameterSetters.typeNumber(
                targetSqlType));
    }

    @Override
    public void setObject(int index, Object value, java.sql.SQLType targetSqlType,
                          int scaleOrLength) throws SQLException {
        setObject(index, value, space.seclume.internal.jdbc.ParameterSetters.typeNumber(
                targetSqlType), scaleOrLength);
    }

    /**
     * Every one of the forty-eight setters above ends here, which is what
     * makes a subclass able to renumber them: a call written
     * {@code {? = call f(?)}} counts its return value as parameter 1, and the
     * statement underneath has only the one placeholder.
     */
    @Override
    public void setSensitive(int parameterIndex, java.lang.foreign.MemorySegment value)
            throws SQLException {
        set(parameterIndex, new space.seclume.internal.jdbc.NativeValue(value));
    }

    void set(int index, Object value) throws SQLException {
        checkOpen();
        space.seclume.internal.jdbc.InLists.Bound list = space.seclume.internal.jdbc.InLists.of(
                value, space.seclume.internal.jdbc.InLists.Dialect.POSTGRESQL);
        lists = space.seclume.internal.jdbc.InLists.note(lists, index, list);
        parameters.set(index, list == null ? value : list.payload());
    }

    /** What has been bound so far - the callable checks its outputs against it. */
    PgParameters parameters() {
        return parameters;
    }

    /** Whether the calendar asks for anything the value does not already say. */
    private static boolean isDefaultCalendar(Calendar calendar) {
        return calendar == null
                || calendar.getTimeZone().equals(java.util.TimeZone.getDefault());
    }

    // ---- metadata --------------------------------------------------------

    @Override
    public ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        prepare();
        describeNow();
        return described == null || described.isEmpty() ? null : new PgResultSetMetaData(described);
    }

    @Override
    public ParameterMetaData getParameterMetaData() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.PlaceholderMetaData.ofText(originalSql);
    }

    // ---- streams: read to the end, then sent as a value ------------------

    /*
     * The same rule as ParameterSetters, which this class does not implement:
     * the stream is read here, a given length is held to, and the value goes
     * out as text or bytea like any other. See StreamValues.
     */

    @Override
    public void setAsciiStream(int index, InputStream stream, int length) throws SQLException {
        setAsciiStream(index, stream, (long) length);
    }

    @SuppressWarnings("deprecation")
    @Override
    public void setUnicodeStream(int index, InputStream stream, int length) throws SQLException {
        throw new SQLFeatureNotSupportedException("setUnicodeStream is deprecated since "
                + "JDBC 2.0 - use setCharacterStream");
    }

    @Override
    public void setBinaryStream(int index, InputStream stream, int length) throws SQLException {
        setBinaryStream(index, stream, (long) length);
    }

    @Override
    public void setAsciiStream(int index, InputStream stream, long length) throws SQLException {
        setString(index, StreamValues.ascii(stream, length));
    }

    @Override
    public void setBinaryStream(int index, InputStream stream, long length) throws SQLException {
        setBytes(index, StreamValues.bytes(stream, length));
    }

    @Override
    public void setAsciiStream(int index, InputStream stream) throws SQLException {
        setAsciiStream(index, stream, StreamValues.UNKNOWN);
    }

    @Override
    public void setBinaryStream(int index, InputStream stream) throws SQLException {
        setBinaryStream(index, stream, StreamValues.UNKNOWN);
    }

    @Override
    public void setCharacterStream(int index, Reader reader, int length) throws SQLException {
        setCharacterStream(index, reader, (long) length);
    }

    @Override
    public void setCharacterStream(int index, Reader reader, long length) throws SQLException {
        setString(index, StreamValues.text(reader, length));
    }

    @Override
    public void setCharacterStream(int index, Reader reader) throws SQLException {
        setCharacterStream(index, reader, StreamValues.UNKNOWN);
    }

    @Override
    public void setNCharacterStream(int index, Reader reader, long length) throws SQLException {
        setCharacterStream(index, reader, length);
    }

    @Override
    public void setNCharacterStream(int index, Reader reader) throws SQLException {
        setCharacterStream(index, reader);
    }

    // ---- the unsupported remainder ---------------------------------------

    @Override
    public void setRef(int index, Ref value) throws SQLException {
        if (value == null) {
            set(index, null);
            return;
        }
        throw unsupported("REF");
    }

    // ---- Blob and Clob: a large object, and its oid as the value ---------

    /*
     * On PostgreSQL a LOB column is an oid, and the value it holds is the
     * number of a large object. So a Blob or Clob parameter creates one and
     * binds its oid - what pgjdbc does, and what Hibernate's @Lob mapping on
     * PostgreSQL depends on.
     *
     * Only inside a transaction. There the large object and the row that
     * points at it commit or roll back together; under auto-commit the object
     * would be committed on its own before the statement runs, and a failed
     * insert would leave it behind. pgjdbc refuses the same.
     *
     * What remains is PostgreSQL's model, not the driver's: a large object
     * outlives the row that pointed at it. Deleting or updating the row leaves
     * the old one in pg_largeobject until something unlinks it - the lo
     * extension's lo_manage trigger, or vacuumlo. See PgLargeObjects.
     */

    @Override
    public void setBlob(int index, Blob value) throws SQLException {
        setLargeObject(index, value == null ? null
                : StreamValues.bytes(value.getBinaryStream(), value.length()), "Blob");
    }

    @Override
    public void setBlob(int index, InputStream stream, long length) throws SQLException {
        setLargeObject(index, StreamValues.bytes(stream, length), "Blob");
    }

    @Override
    public void setBlob(int index, InputStream stream) throws SQLException {
        setBlob(index, stream, StreamValues.UNKNOWN);
    }

    @Override
    public void setClob(int index, Clob value) throws SQLException {
        setClobText(index, value == null ? null
                : StreamValues.text(value.getCharacterStream(), value.length()));
    }

    @Override
    public void setClob(int index, Reader reader, long length) throws SQLException {
        setClobText(index, StreamValues.text(reader, length));
    }

    @Override
    public void setClob(int index, Reader reader) throws SQLException {
        setClob(index, reader, StreamValues.UNKNOWN);
    }

    @Override
    public void setNClob(int index, NClob value) throws SQLException {
        setClob(index, value);
    }

    @Override
    public void setNClob(int index, Reader reader, long length) throws SQLException {
        setClob(index, reader, length);
    }

    @Override
    public void setNClob(int index, Reader reader) throws SQLException {
        setClob(index, reader);
    }

    /** A Clob's text is stored as UTF-8 - the encoding this driver talks. */
    private void setClobText(int index, String text) throws SQLException {
        setLargeObject(index, text == null ? null
                : text.getBytes(java.nio.charset.StandardCharsets.UTF_8), "Clob"); // seclume-allow: user payload on its way into a large object, not a secret
    }

    private void setLargeObject(int index, byte[] content, String kind) throws SQLException {
        checkOpen();
        if (content == null) {
            setNull(index, java.sql.Types.BIGINT);
            return;
        }
        if (connection.getAutoCommit()) {
            throw new SQLException("a " + kind + " parameter on PostgreSQL creates a large "
                    + "object, and outside a transaction it would outlive a statement that "
                    + "fails - call setAutoCommit(false) first, or map the column as bytea "
                    + "or text and use setBytes or setString", "25P01");
        }
        setLong(index, new PgLargeObjects(connection).create(content));
    }

    @Override
    public void setArray(int index, Array value) throws SQLException {
        if (value == null) {
            set(index, null);
            return;
        }
        throw unsupported("ARRAY");
    }

    @Override
    public void setRowId(int index, RowId value) throws SQLException {
        if (value == null) {
            set(index, null);
            return;
        }
        throw unsupported("ROWID");
    }

    @Override
    public void setSQLXML(int index, SQLXML value) throws SQLException {
        // As its text; the server parses it into the xml column.
        set(index, value == null ? null : value.getString());
    }

    @Override
    public void setNString(int index, String value) throws SQLException {
        // PostgreSQL has no separate N-character format; text is always Unicode.
        set(index, value);
    }

    @Override
    public void setURL(int index, URL value) throws SQLException {
        // As its text: PostgreSQL has no type of its own for a URL.
        set(index, value == null ? null : value.toString());
    }

    private static SQLFeatureNotSupportedException unsupported(String type) {
        return new SQLFeatureNotSupportedException(
                "seclume does not send " + type + " parameters yet");
    }

    @Override
    public void close() {
        if (!isClosed() && prepared && !released) {
            released = true;
            try {
                // Back to the connection rather than to the server. It keeps
                // the plan for the next caller who asks for the same SQL, or
                // releases it when the cache is full or switched off - and
                // releasing rides along with the next statement, so nobody
                // waits for it either way.
                //
                // described is the condition, not a convenience: it is set once
                // the statement has run, so a plan whose Parse failed is never
                // offered to anybody.
                connection.releasePlan(planSql, name, described);
            } catch (SQLException ignored) {
                // On close the server plan is the lesser problem; it goes
                // away with the connection at the latest anyway.
            }
        }
        super.close();
    }

    /**
     * A statement named in a message, with its values taken out.
     *
     * <p>The text must not travel: a literal in it can be a password, a card
     * number or a person, and an exception message is precisely what ends up
     * in a log. The shape says which statement it was and carries none of
     * that - see {@link space.seclume.QueryFingerprint}.
     */
    private static String shape(String sql) {
        return space.seclume.QueryFingerprint.of(sql,
                space.seclume.QueryFingerprint.Dialect.POSTGRESQL);
    }

}
