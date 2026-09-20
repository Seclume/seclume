package space.seclume.postgresql.jdbc;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * PostgreSQL's large objects, which are not a column type but a side table.
 *
 * <p>A {@code bytea} column holds its bytes in the row. A large object does
 * not: the bytes live in {@code pg_largeobject}, the row holds only an
 * {@code oid} pointing at them, and the two have almost nothing in common
 * beyond both being binary. In particular a large object <b>outlives the row
 * that referenced it</b> - deleting the row leaks the object until somebody
 * calls {@link #delete}, which is the single most common mistake made with
 * this feature and the reason it is spelled out here.
 *
 * <p>This is deliberately not reachable through {@code Connection.createBlob}.
 * That method promises an empty writable {@code Blob} with no side effects,
 * and creating a large object is a write to the database that leaves
 * something behind whether or not the caller ever stores the oid. Handing that
 * back as a {@code Blob} would hide a row-leaking allocation behind a factory
 * method. So it is asked for by name:
 *
 * <pre>{@code
 * PgLargeObjects lo = connection.unwrap(PgLargeObjects.class);
 * long oid = lo.create(bytes);
 * try (PreparedStatement s = connection.prepareStatement(
 *         "insert into document (id, body) values (?, ?)")) {
 *     s.setLong(1, 1);
 *     s.setLong(2, oid);   // an oid column takes the number
 *     s.executeUpdate();
 * }
 * }</pre>
 *
 * <p>Reading needs none of this: {@code getBlob} and {@code getBinaryStream}
 * on an {@code oid} column follow the pointer by themselves.
 *
 * <p>Everything here goes through the server's SQL functions -
 * {@code lo_from_bytea}, {@code lo_get}, {@code lo_unlink} - rather than
 * through the protocol's fast-path call. Fast path is one round trip cheaper
 * and a great deal more to get wrong, and a large object is by definition not
 * the place where one round trip decides anything.
 */
public final class PgLargeObjects {

    /** {@code INV_READ} from the server's {@code libpq-fs.h}. */
    private static final int INV_READ = 0x40000;

    /**
     * The largest slice read in one round trip.
     *
     * <p>A megabyte is big enough that a 50 MB object costs fifty round trips
     * rather than fifty thousand, and small enough that reading one does not
     * put the whole object on the heap at once - which is the entire point of
     * a large object over a {@code bytea}.
     */
    static final int CHUNK = 1 << 20;

    private final Connection connection;

    PgLargeObjects(Connection connection) {
        this.connection = connection;
    }

    /**
     * Creates a large object holding these bytes and returns its oid.
     *
     * <p>Nothing references it yet. If the statement that would store the oid
     * is never run, or its transaction rolls back while this one did not, the
     * object stays in the database until {@link #delete} removes it.
     */
    public long create(byte[] content) throws SQLException {
        try (PreparedStatement s = connection.prepareStatement("select lo_from_bytea(0, ?)")) {
            s.setBytes(1, content);
            try (ResultSet rows = s.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    /** The bytes of a large object, whole. */
    public byte[] read(long oid) throws SQLException {
        try (PreparedStatement s = connection.prepareStatement("select lo_get(?)")) {
            s.setLong(1, oid);
            try (ResultSet rows = s.executeQuery()) {
                rows.next();
                return rows.getBytes(1); // seclume-allow: the content of a large object is user payload, not a secret
            }
        }
    }

    /** The bytes of a large object, a piece at a time. */
    public InputStream stream(long oid) throws SQLException {
        return new LargeObjectStream(this, oid);
    }

    /**
     * How long a large object is, without reading it.
     *
     * <p>{@code lo_open} needs a transaction, and a single statement is one -
     * so the descriptor is opened and seeked to the end inside the same
     * {@code select}, and is closed when that statement's transaction ends.
     * Doing it in two statements would work only with autocommit off, and
     * would fail in the case most callers are in.
     */
    public long length(long oid) throws SQLException {
        try (PreparedStatement s = connection.prepareStatement(
                "select lo_lseek64(lo_open(?, " + INV_READ + "), 0, 2)")) {
            s.setLong(1, oid);
            try (ResultSet rows = s.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    /**
     * Removes a large object.
     *
     * <p>The counterpart to {@link #create}, and the one an application has to
     * remember to call: no row deletion does it, and no cascade reaches it.
     */
    public void delete(long oid) throws SQLException {
        try (PreparedStatement s = connection.prepareStatement("select lo_unlink(?)")) {
            s.setLong(1, oid);
            s.executeQuery().close();
        }
    }

    /**
     * A slice, zero-based, as {@code lo_get} counts.
     *
     * <p>A read past the end returns fewer bytes rather than failing, which is
     * how the stream above knows it has arrived.
     */
    byte[] slice(long oid, long offset, int length) throws SQLException {
        try (PreparedStatement s = connection.prepareStatement("select lo_get(?, ?, ?)")) {
            s.setLong(1, oid);
            s.setLong(2, offset);
            s.setInt(3, length);
            try (ResultSet rows = s.executeQuery()) {
                rows.next();
                return rows.getBytes(1); // seclume-allow: the content of a large object is user payload, not a secret
            }
        }
    }

    /** Reads a large object a chunk at a time, so it is never whole on the heap. */
    private static final class LargeObjectStream extends InputStream {

        private final PgLargeObjects objects;
        private final long oid;
        private byte[] chunk = new byte[0]; // seclume-allow: user payload, not a secret
        private int at;
        private long offset;
        private boolean ended;

        LargeObjectStream(PgLargeObjects objects, long oid) {
            this.objects = objects;
            this.oid = oid;
        }

        @Override
        public int read() throws java.io.IOException {
            return fill() ? chunk[at++] & 0xff : -1;
        }

        @Override
        public int read(byte[] into, int from, int length) throws java.io.IOException {
            if (length == 0) {
                return 0;
            }
            if (!fill()) {
                return -1;
            }
            int taken = Math.min(length, chunk.length - at);
            System.arraycopy(chunk, at, into, from, taken);
            at += taken;
            return taken;
        }

        private boolean fill() throws java.io.IOException {
            if (at < chunk.length) {
                return true;
            }
            if (ended) {
                return false;
            }
            try {
                chunk = objects.slice(oid, offset, CHUNK);
            } catch (SQLException noSuchObject) {
                throw new java.io.IOException(noSuchObject);
            }
            at = 0;
            offset += chunk.length;
            ended = chunk.length < CHUNK;
            return chunk.length > 0;
        }
    }
}
