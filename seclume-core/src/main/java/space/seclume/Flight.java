package space.seclume;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

/**
 * The last few messages this connection sent and received, and nothing of
 * what was in them.
 *
 * <p>There is one class of defect in a hand-written protocol driver that is
 * worse than all the others, and it is not a crash. It is a connection that is
 * <b>one message behind</b>: a request written for a state the server is not
 * in, an answer read against the wrong description, a token left unread at the
 * head of the next statement's reply. Nothing fails at the moment it goes
 * wrong. Three calls later something fails, in code that did nothing, and the
 * stack trace points at the innocent caller.
 *
 * <p>Nothing that looks at one statement can see it, because every statement
 * looks fine. What shows it immediately is the <b>order</b>: a list of what
 * went out and what came back, in sequence, with the types and the lengths.
 *
 * <pre>
 * -&gt; 8  Q      (Query)
 * &lt;- 33 T      (RowDescription)
 * &lt;- 28 D      (DataRow)
 * &lt;- 13 C      (CommandComplete)
 * &lt;- 5  Z      (ReadyForQuery)
 * </pre>
 *
 * <h2>What it carries, and what it must never carry</h2>
 *
 * <p>Direction, message type and byte count. <b>No payload, ever.</b> A
 * recorder that kept the bytes would be a recorder that keeps a password
 * during the handshake and a customer's name during a query, in a ring buffer,
 * in the heap, available to whatever reads a diagnostic. That is the one thing
 * this library exists to prevent, so the recording is of the shape of the
 * conversation and never of its content - the same rule
 * {@link QueryFingerprint} applies to statements, applied to messages.
 *
 * <p>The count is not content. It is what makes a desynchronisation visible:
 * a length that does not match the type is how nearly every one of them looks
 * from the outside.
 *
 * <h2>Off unless asked for</h2>
 *
 * <p>Not on by default, and the reason is a principle rather than a
 * measurement: this sits on the path of every message of every connection, and
 * a diagnostic that every application pays for so that one of them can debug
 * something is the wrong trade. Switched on with the system property
 * {@code seclume.flight}, it costs a bounded ring per connection and one
 * branch per message.
 *
 * <pre>
 * -Dseclume.flight=64      # or "on", for the default of 32
 * </pre>
 *
 * <p><b>Process-wide and not per connection, for now.</b> A URL option would
 * be better - one data source recording while another does not - and it means
 * a component on every driver's settings record and every constructor that
 * builds one. That is churn a diagnostic has not earned yet; it is named here
 * rather than left to be discovered.
 *
 * <p>When it is on, what it recorded is <b>attached to the failure</b> - a
 * broken connection says what the last messages were, in the exception that
 * reports it, which is the one place somebody is certain to look.
 */
public interface Flight {

    /**
     * One message, in one direction.
     *
     * @param bytes how many bytes it was, or {@code -1} where the count is
     *              withheld - see {@link #WITHHELD}
     */
    record Message(boolean outgoing, String type, int bytes) {

        @Override
        public String toString() {
            return (outgoing ? "-> " : "<- ") + (bytes < 0 ? "?" : bytes) + " " + type;
        }
    }

    /**
     * The byte count of a message that carries a credential is not recorded.
     *
     * <p>Found by reading this recorder's own output. A PostgreSQL
     * {@code PasswordMessage} under SCRAM has a length decided by the
     * protocol; under <b>cleartext</b> authentication its length is the
     * password's length plus a constant, and a ring buffer holding that is a
     * ring buffer holding how long the password is. That is not the password,
     * and it is not nothing either: it is the single most useful fact for
     * anybody about to guess one.
     *
     * <p>So the type is recorded and the count is not. The shape of the
     * conversation survives - which is all this was ever for.
     */
    int WITHHELD = -1;

    /**
     * What this connection last sent and received, oldest first.
     *
     * <p>Empty when the recorder is off, which is the default - and empty
     * rather than an exception, because a caller that asks for a diagnostic
     * should not have to handle not getting one.
     */
    List<Message> recent();

    /** How many messages this connection has sent and received in all. */
    long messages();

    /**
     * The recorder of any seclume connection - also through a pool.
     *
     * @throws SQLException if this is not a seclume connection
     */
    static Flight of(Connection connection) throws SQLException {
        if (connection instanceof Flight flight) {
            return flight;
        }
        if (connection.isWrapperFor(Flight.class)) {
            return connection.unwrap(Flight.class);
        }
        throw new SQLException("this is not a seclume connection, so it cannot say what it "
                + "last sent: " + connection.getClass().getName());
    }
}
