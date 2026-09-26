package space.seclume;

import java.lang.foreign.MemorySegment;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Reading a column that holds a secret, without it becoming a {@code String}.
 *
 * <p>This library exists because a database password must not be a heap
 * object. That was always half the problem, and the half nobody says out loud
 * is the other one: <b>a great many applications store secrets in the
 * database.</b> API keys, webhook signing keys, OAuth refresh tokens, TOTP
 * seeds, the credentials of every third-party system a tenant has connected.
 * Every one of them is read with {@code getString}, and the moment it is, it
 * is a heap object with the same lifetime as the connection password had
 * before this library was written.
 *
 * <p>The row is already in native memory - it has to be, it came off a socket
 * - and every driver here reads values out of the receive buffer in place.
 * {@code getString} copies a window of that buffer into a byte array and then
 * into a {@code String}, and both of those outlive the call and end up in a
 * heap dump. This hands the caller the window instead:
 *
 * <pre>
 * try (SecretScope key = SecretScope.allocate(128);
 *      ResultSet rows = statement.executeQuery("select signing_key from tenant where id = ?")) {
 *     if (rows.next()) {
 *         key.length(Sensitive.of(rows).readInto(1, key.segment()));
 *         signature = hmac(key.secret(), payload);
 *     }
 * }
 * </pre>
 *
 * <p>The three lines are in that order for a reason:
 * {@link space.seclume.secret.SecretScope#segment()} is the whole allocation
 * and is what a value is written <b>into</b>;
 * {@link space.seclume.secret.SecretScope#secret()} is the part that has been
 * written and is what a value is read <b>out of</b>. Handing {@code secret()}
 * to this method gives it a segment of length zero, which is refused rather
 * than silently accepted.
 *
 * <p><b>What this does and does not promise.</b> It promises that the value
 * does not become a heap object <i>on the way out of the driver</i>. It cannot
 * promise anything about what the caller does with the segment afterwards, and
 * it does not try to: a caller who copies it into a {@code String} on the next
 * line has undone it, and no API can prevent that. What it can do is make the
 * careful path available, which it was not before - the only way to read a
 * column was through a {@code String}.
 *
 * <p>The receive buffer is wiped when the next answer overwrites it, which is
 * the same guarantee the rows have always had here and is why this is a
 * <b>window</b> and not a promise of lifetime: what is read has to be read
 * before the next statement runs on that connection.
 *
 * <p><b>Bytes, not text.</b> What is copied is exactly what the server sent
 * for that column, in the column's own encoding. No decoding, no trimming, no
 * charset conversion - all three of those need a decoder, and a decoder needs
 * somewhere to put its output. For a key, a token or a hash that is what is
 * wanted anyway; for a name it is not, and a name is not what this is for.
 */
public interface Sensitive {

    /**
     * Copies the current row's column into native memory the caller owns.
     *
     * <p>The caller's segment is usually a {@link space.seclume.secret.SecretScope},
     * which is locked against paging and wiped on close - but any segment
     * will do, and the choice of where the secret lives belongs to whoever
     * owns it rather than to this driver.
     *
     * @param columnIndex the 1-based JDBC column index
     * @param target      where to put it; must hold {@link #length} bytes
     * @return how many bytes were written, or -1 when the column is SQL NULL
     * @throws SQLException if the row or column is not there, or the segment
     *                      is too small - never silently truncated, because a
     *                      key cut in half fails somewhere far from here
     */
    int readInto(int columnIndex, MemorySegment target) throws SQLException;

    /**
     * How many bytes the column holds, for sizing a segment.
     *
     * <p>Costs nothing: the length is already known, it is what the decoder
     * would have used.
     *
     * @return the byte count, or -1 when the column is SQL NULL
     */
    int length(int columnIndex) throws SQLException;

    /**
     * The native reader of any seclume result set - also through a pool.
     *
     * @throws SQLException if this is not a seclume result set
     */
    static Sensitive of(ResultSet rows) throws SQLException {
        if (rows instanceof Sensitive sensitive) {
            return sensitive;
        }
        if (rows.isWrapperFor(Sensitive.class)) {
            return rows.unwrap(Sensitive.class);
        }
        throw new SQLException("this is not a seclume result set, so its columns cannot be "
                + "read without becoming a String: " + rows.getClass().getName());
    }
}
