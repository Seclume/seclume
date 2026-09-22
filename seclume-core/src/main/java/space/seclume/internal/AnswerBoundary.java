package space.seclume.internal;

/**
 * Where one answer ends, and nothing else about the protocol.
 *
 * <p>Whoever relays a protocol relays bytes it does not read. That is the whole point of
 * carrying the wire protocol instead of rendered text - types, cursors, large
 * objects and prepared plans keep working precisely because nothing in the
 * middle interprets them. But <b>one</b> question has to be answered in the
 * middle, and it cannot be avoided: a relay that counts answers has to know where
 * one stops.
 *
 * <p>That is the entire interface, and it is an interface rather than one
 * method somewhere because there are four protocols and they disagree about
 * it:
 *
 * <table border="1">
 *   <caption>The end of an answer, per protocol</caption>
 *   <tr><th>PostgreSQL</th><td>{@code ReadyForQuery} - which is also the
 *       protocol's own statement that the conversation is at rest</td></tr>
 *   <tr><th>MySQL</th><td>the terminating OK, EOF or ERR packet of the
 *       command</td></tr>
 *   <tr><th>SQL Server</th><td>the final {@code DONE} token - not a
 *       {@code DONE_IN_PROC}, of which one arrives per statement in a
 *       batch</td></tr>
 *   <tr><th>Oracle</th><td>the end-of-call marker of the TTC round</td></tr>
 * </table>
 *
 * <p>Writing that table before the first implementation was deliberate. A
 * relay built around one protocol and generalised afterwards bakes that
 * protocol's shape into itself, and this project has made that mistake three
 * times in its type mapping already - each time found by the differential run
 * rather than by the author.
 *
 * <p><b>Each implementation lives with its protocol, not with the relay.</b>
 * Oracle is why that is not a matter of taste: the end of a call there can only
 * be found by walking TTC messages, which this library's Oracle driver already
 * does. A relay with a walker of its own would be the same reader twice, and
 * two readers of one protocol drift.
 *
 * <p><b>Stateful, and one per direction of one connection.</b> A message can
 * be split across reads at any byte, so the implementation carries whatever it
 * has half seen.
 */
public interface AnswerBoundary {

    /**
     * How many of these bytes finish the answer being read.
     *
     * @param data freshly arrived bytes from the server
     * @param offset where they start
     * @param length how many there are
     * @return the number of bytes from {@code offset} that belong to the
     *         answer, once it ends inside this block; {@code -1} while it does
     *         not. Anything after that belongs to the next answer and the
     *         caller keeps it
     */
    int endOfAnswer(byte[] data, int offset, int length);

    /** Forgets what was half seen - for a stream that is starting over. */
    void reset();
}
