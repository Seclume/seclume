package space.seclume;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * A connection source that can say, without waiting, whether it has a
 * connection to lend right now - for callers that must not block, such as
 * the R2DBC driver on the thread of whoever subscribed.
 *
 * <p>Implemented by {@code SeclumePool}. Every rule of an ordinary borrow
 * holds: the reset of the last borrow is confirmed before the connection goes
 * out, a connection past its lifetime or its credential does not go out, and
 * one that has been idle long enough to be asked whether it is still alive is
 * left to the ordinary borrow, which may wait for that answer.
 */
public interface ImmediateBorrow {

    /**
     * A connection, if one can be lent without waiting for anything - not for
     * a reset's answer, a validation, a new connection or another borrower -
     * or null. A null says nothing about whether {@code getConnection()}
     * would succeed; it would wait.
     */
    Connection getConnectionIfReady() throws SQLException;
}
