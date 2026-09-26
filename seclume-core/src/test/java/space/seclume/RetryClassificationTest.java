package space.seclume;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLTimeoutException;
import java.sql.SQLTransientException;

import org.junit.jupiter.api.Test;

/**
 * The half of a retry that decides whether there is one.
 *
 * <p>The loop is three lines and nobody gets it wrong. What people get wrong
 * is the question it asks, and they get it wrong in both directions: too
 * narrow and a deadlock reaches a user who did nothing; too wide and a unique
 * constraint is retried three times before failing identically, or a dead
 * connection is retried on itself.
 *
 * <p>No server needed - this is a decision about exceptions.
 */
class RetryClassificationTest {

    private static SQLException with(String state) {
        return new SQLException("whatever the server said", state);
    }

    @Test
    void theTransactionRollbackClassIsRetried() {
        // PostgreSQL and MySQL say 40001 themselves, and the SQL Server
        // driver maps its deadlock number onto it because the server sends
        // no SQLState.
        assertTrue(Retry.worthRetrying(with("40001")), "a serialization failure");
        assertTrue(Retry.worthRetrying(with("40P01")), "PostgreSQL's deadlock");
        assertTrue(Retry.worthRetrying(with("40003")), "completion unknown");
    }

    @Test
    void oraclesDeadlockIsRetriedByItsTypeNotItsState() {
        // ojdbc gives ORA-00060 the state 61000 and ORA-08177 72000, neither
        // of which says "run it again"; the type does.
        assertTrue(Retry.worthRetrying(new java.sql.SQLTransactionRollbackException(
                "ORA-00060", "61000", 60)), "a deadlock");
        assertTrue(Retry.worthRetrying(new java.sql.SQLTransactionRollbackException(
                "ORA-08177", "72000", 8177)), "cannot serialize");
        assertFalse(Retry.worthRetrying(new SQLException("ORA-12899", "72000", 12899)),
                "the same state on a value that does not fit");
    }

    @Test
    void aConnectionThatIsGoneIsNotRetriedOnItself() {
        // The trap this is here for: the block would run again on the same
        // broken connection, fail identically, and the last failure is the one
        // the caller sees - which says nothing about the first.
        assertFalse(Retry.worthRetrying(with("08006")), "connection failure");
        assertFalse(Retry.worthRetrying(with("08001")), "cannot connect");
        assertFalse(Retry.worthRetrying(
                new SQLNonTransientConnectionException("gone", "08006")));
    }

    @Test
    void whatWillHappenAgainIsNotRetried() {
        assertFalse(Retry.worthRetrying(with("23505")), "unique violation");
        assertFalse(Retry.worthRetrying(with("23000")), "constraint violated");
        assertFalse(Retry.worthRetrying(with("42601")), "syntax error");
        assertFalse(Retry.worthRetrying(with("42S02")), "no such table");
        assertFalse(Retry.worthRetrying(with("28000")), "authentication");
        assertFalse(Retry.worthRetrying(with("22001")), "value too long");
    }

    @Test
    void aDeadlineThatPassedIsNotSpentAgain() {
        // SQLTimeoutException is checked before the state, because the state a
        // timeout carries is whatever the protocol reported the cancellation
        // as - and on one of the four it carries 57014, which would otherwise
        // read as a plain cancellation.
        assertFalse(Retry.worthRetrying(
                new SQLTimeoutException("the deadline passed", "57014")));
        assertFalse(Retry.worthRetrying(with("57014")), "somebody cancelled it");
    }

    @Test
    void theJdbcTypeIsBelievedWhenThereIsNoState() {
        assertTrue(Retry.worthRetrying(new SQLTransientException("try again", (String) null)));
        // And without either, nothing is known - which is not a reason to run
        // an unknown failure again.
        assertFalse(Retry.worthRetrying(new SQLException("something", (String) null)));
        assertFalse(Retry.worthRetrying(with("")), "an empty state says nothing");
    }

    /**
     * A commit whose outcome is unknown is the one failure a retry is most
     * tempted by and must never touch.
     *
     * <p>It looks transient - a network blip at the last moment - and running
     * the block again usually works. When the first commit was applied, that
     * second run is the same work done twice. This is here so that nobody
     * widening the classification later can do it without meeting this
     * sentence first.
     */
    @Test
    void aCommitWhoseOutcomeIsUnknownIsNeverRetried() {
        SQLException unknown = TransactionResolutionUnknownException.duringCommit(
                new java.sql.SQLNonTransientConnectionException("gone", "08006"));
        assertInstanceOf(TransactionResolutionUnknownException.class, unknown);
        assertEquals("08007", unknown.getSQLState());
        assertFalse(Retry.worthRetrying(unknown));
    }

    /** And the classification only ever touches a lost connection. */
    @Test
    void aCommitTheServerAnsweredKeepsItsState() {
        SQLException refused = with("23505");
        assertSame(refused, TransactionResolutionUnknownException.duringCommit(refused));
        SQLException deadlock = with("40001");
        assertSame(deadlock, TransactionResolutionUnknownException.duringCommit(deadlock),
                "a commit refused for a deadlock was rolled back - that outcome is known, "
                        + "and it is the one case where running it again is right");
    }
}
