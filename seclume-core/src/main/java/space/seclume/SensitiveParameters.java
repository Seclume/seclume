package space.seclume;

import java.lang.foreign.MemorySegment;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Storing a secret in the database without it becoming a {@code String}.
 *
 * <p>The counterpart to {@link Sensitive}, and the reason that one is only
 * half a feature on its own. An application that reads an API key off the heap
 * has a problem; an application that <b>writes</b> one with
 * {@code setString} has the same problem, in the same process, for the same
 * lifetime. Rotating a key, storing a freshly issued refresh token, saving a
 * TOTP seed at enrolment - all of them go through a parameter.
 *
 * <pre>
 * try (SecretScope key = SecretScope.fromProvider(generator);
 *      PreparedStatement update = connection.prepareStatement(
 *              "update tenant set signing_key = ? where id = ?")) {
 *     SensitiveParameters.of(update).setSensitive(1, key.secret());
 *     update.setLong(2, tenantId);
 *     update.executeUpdate();
 * }
 * </pre>
 *
 * <p>Note the symmetry with the read side: a value is read <b>into</b>
 * {@link space.seclume.secret.SecretScope#segment()} and written <b>from</b>
 * {@link space.seclume.secret.SecretScope#secret()}, because the first is the
 * whole allocation and the second is the part that holds something.
 *
 * <h2>Bytes, as they are</h2>
 *
 * <p>What goes on the wire is exactly the bytes of the segment, as the value
 * of a <b>text</b> parameter - which is what a {@code text}, {@code varchar}
 * or {@code varchar2} column wants, and is where keys and tokens are kept. No
 * encoding happens, because encoding needs a buffer and a buffer is the thing
 * being avoided; a caller storing into a binary column should keep the value
 * as text (base64 or hex) or use {@code setBytes} and accept the heap.
 *
 * <h2>The segment has to outlive the execute</h2>
 *
 * <p>Nothing is copied here - copying would need a second native allocation
 * with a lifetime and an owner. The driver holds the caller's segment and
 * reads it when the statement is sent, so the scope it came from must still be
 * open then. That is the same contract a {@code byte[]} parameter has always
 * had; it is written down here because a closed arena fails louder than a
 * mutated array.
 */
public interface SensitiveParameters {

    /**
     * Binds a parameter from native memory.
     *
     * @param parameterIndex the 1-based JDBC parameter index
     * @param value          the bytes to send; usually
     *                       {@link space.seclume.secret.SecretScope#secret()}
     * @throws SQLException if the index is not a parameter of this statement
     */
    void setSensitive(int parameterIndex, MemorySegment value) throws SQLException;

    /**
     * The native binder of any seclume prepared statement - also through a
     * pool.
     *
     * @throws SQLException if this is not a seclume prepared statement
     */
    static SensitiveParameters of(PreparedStatement statement) throws SQLException {
        if (statement instanceof SensitiveParameters sensitive) {
            return sensitive;
        }
        if (statement.isWrapperFor(SensitiveParameters.class)) {
            return statement.unwrap(SensitiveParameters.class);
        }
        throw new SQLException("this is not a seclume prepared statement, so a parameter "
                + "cannot be bound without becoming a String: "
                + statement.getClass().getName());
    }
}
