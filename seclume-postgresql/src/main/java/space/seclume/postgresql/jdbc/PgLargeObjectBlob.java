package space.seclume.postgresql.jdbc;

import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Blob;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

/**
 * A {@link Blob} that is a pointer rather than a value.
 *
 * <p>This is the one place in the project where a {@code Blob} keeps JDBC's
 * original promise in full: the bytes are still in the database, nothing is
 * read until somebody asks, and a hundred-megabyte object costs a hundred
 * megabytes of heap only if the caller insists on {@code getBytes} for all of
 * it. {@link space.seclume.internal.jdbc.Lobs} says plainly that it cannot do
 * that for a {@code bytea}; a large object is why the distinction was worth
 * keeping.
 *
 * <p>The object stays readable for as long as its connection does. It is not
 * tied to the result set it came from, which is the behaviour an application
 * that hands a {@code Blob} to something else depends on - but it does mean a
 * closed connection turns every later read into an error rather than into
 * stale data.
 *
 * <p>Read-only, like everything handed out of a result set here. Writing
 * through a large object is real work on the server and is asked for by name,
 * through {@link PgLargeObjects}.
 */
final class PgLargeObjectBlob implements Blob {

    private final PgLargeObjects objects;
    private final long oid;
    private boolean freed;

    PgLargeObjectBlob(PgLargeObjects objects, long oid) {
        this.objects = objects;
        this.oid = oid;
    }

    /** The oid, for an application that wants to keep or delete the object. */
    long oid() {
        return oid;
    }

    @Override
    public long length() throws SQLException {
        alive();
        return objects.length(oid);
    }

    @Override
    public byte[] getBytes(long pos, int length) throws SQLException {
        alive();
        if (pos < 1) {
            throw new SQLException("a Blob position counts from 1, not " + pos, "22003");
        }
        return objects.slice(oid, pos - 1, length);
    }

    @Override
    public InputStream getBinaryStream() throws SQLException {
        alive();
        return objects.stream(oid);
    }

    @Override
    public InputStream getBinaryStream(long pos, long length) throws SQLException {
        // A bounded stream over a large object would be a second implementation
        // of the chunking for the sake of one rarely used overload; the slice is
        // the same answer and the caller has already named a length, so the size
        // is their decision rather than a surprise.
        return new java.io.ByteArrayInputStream(getBytes(pos, (int) Math.min(length, Integer.MAX_VALUE)));
    }

    @Override
    public void free() {
        freed = true;
    }

    /**
     * Searching inside a large object would mean streaming it through the
     * driver to do what the server can do in the query. Refused rather than
     * offered as the slow thing that looks free.
     */
    @Override
    public long position(byte[] pattern, long start) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not search inside a large object - use position() in SQL");
    }

    @Override
    public long position(Blob pattern, long start) throws SQLException {
        return position((byte[]) null, start);
    }

    @Override
    public int setBytes(long pos, byte[] bytes) throws SQLException {
        throw readOnly();
    }

    @Override
    public int setBytes(long pos, byte[] bytes, int offset, int length) throws SQLException {
        throw readOnly();
    }

    @Override
    public OutputStream setBinaryStream(long pos) throws SQLException {
        throw readOnly();
    }

    @Override
    public void truncate(long length) throws SQLException {
        throw readOnly();
    }

    private void alive() throws SQLException {
        if (freed) {
            throw new SQLException("this Blob has been freed");
        }
    }

    private static SQLFeatureNotSupportedException readOnly() {
        return new SQLFeatureNotSupportedException(
                "this Blob points at a large object and came out of a read-only result set - "
                + "write one with connection.unwrap(PgLargeObjects.class)");
    }
}
