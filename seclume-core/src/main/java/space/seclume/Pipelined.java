package space.seclume;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * A connection that can hold writes back and send them together.
 *
 * <p>Implemented by the driver connections; used through {@link Pipeline},
 * which is what an application writes. Nothing here is meant to be called
 * directly - the block form is what makes the two halves impossible to forget.
 */
public interface Pipelined {

    /**
     * From here on, a write that nobody looks at is buffered instead of sent.
     *
     * @throws SQLException if the connection is in auto-commit - a block whose
     *         statements commit one by one would leave half a unit of work
     *         behind when the third one fails
     */
    void beginPipeline() throws SQLException;

    /** Sends whatever is still buffered and reads the answers. */
    long[] endPipeline() throws SQLException;

    /** Whether writes are being held back right now. */
    boolean isPipelining();

    /**
     * The one that keeps the promise: everything buffered goes out now.
     *
     * <p>Called by the driver itself whenever an answer is actually needed -
     * a query, a commit, a requested update count. That is why the block never
     * hands out a number that was not asked of the server.
     */
    void flushPipeline() throws SQLException;

    /** The connection as a pipeline, or {@code null} if it is not one. */
    static Pipelined of(Connection connection) throws SQLException {
        if (connection instanceof Pipelined pipelined) {
            return pipelined;
        }
        if (connection != null && connection.isWrapperFor(Pipelined.class)) {
            return connection.unwrap(Pipelined.class);
        }
        return null;
    }
}
