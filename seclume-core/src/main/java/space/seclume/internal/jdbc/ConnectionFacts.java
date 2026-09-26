package space.seclume.internal.jdbc;

/**
 * What a JDBC connection knows about itself that the server session does not
 * say - handed from a connection that gives its session up to the one that
 * takes it over.
 *
 * <p>The server keeps the transaction, the isolation it runs under and every
 * plan it has prepared. The connection object keeps its own copy of some of
 * that, and the counters it names things by. A connection put on a taken-over
 * session without these reports auto-commit where a transaction is open, the
 * default isolation where another one is in force, and names its next prepared
 * statement {@code seclume_1} although the server still holds a plan of that
 * name.
 *
 * @param autoCommit  whether the connection commits every statement - false
 *                    inside an open transaction
 * @param readOnly    what {@code setReadOnly} last said
 * @param isolation   a {@code Connection.TRANSACTION_*} constant
 * @param statements  the last number used in a server-side statement name
 * @param savepoints  the last number used in a savepoint name
 */
public record ConnectionFacts(boolean autoCommit, boolean readOnly, int isolation,
                              long statements, int savepoints) {

    /** What a fresh connection would have - auto-commit on, nothing named yet. */
    public static ConnectionFacts fresh(int isolation) {
        return new ConnectionFacts(true, false, isolation, 0, 0);
    }
}
