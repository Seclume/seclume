package space.seclume.mongodb.driver;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.bson.BsonDocument;
import org.bson.RawBsonDocument;
import org.bson.codecs.BsonDocumentCodec;

import com.mongodb.client.ClientSession;
import com.mongodb.client.MongoClient;

import space.seclume.mongodb.driver.internal.LogicalSession;

/**
 * A session carried on by another client - in another process, on another
 * host - with its transaction still open.
 *
 * <p>A MongoDB transaction belongs to the logical session the commands name
 * ({@code lsid}, {@code txnNumber}), not to the connection they go on: any
 * client logged in as the same user can continue it by naming it. What
 * {@link #handOff} returns is that name and the driver's bookkeeping - the
 * transaction's state and options, the causal-consistency times. No
 * credential, no key: but whoever holds it and can log in as the session's
 * user can act in the transaction, so it travels as the session itself would.
 *
 * <pre>{@code
 * byte[] state = SeclumeSessions.handOff(session);    // here: let go
 * ...
 * ClientSession same = SeclumeSessions.takeUp(client, state);   // there: carry on
 * collection.insertOne(same, document);
 * same.commitTransaction();
 * }</pre>
 *
 * <p>Not handed off: a snapshot session, and on a sharded cluster a
 * transaction pinned to one mongos. Open cursors are closed, not carried.
 */
public final class SeclumeSessions {

    private SeclumeSessions() {
    }

    /**
     * Lets go of {@code session} without ending it and returns its state. The
     * session is closed here afterwards, its transaction left open on the
     * server, and its server session not reused by this client.
     *
     * @throws IllegalArgumentException when it is not a session of seclume's driver
     * @throws IllegalStateException    when it is closed, or cannot be carried
     */
    public static byte[] handOff(ClientSession session) {
        if (!(session instanceof SeclumeClientSession ours)) {
            throw new IllegalArgumentException("not a session of seclume's MongoDB driver");
        }
        RawBsonDocument raw = new RawBsonDocument(ours.handOff().toBson(),
                new BsonDocumentCodec());
        ByteBuffer bytes = raw.getByteBuffer().asNIO();
        byte[] out = new byte[bytes.remaining()];
        bytes.get(out);
        return out;
    }

    /**
     * A session of {@code client} that carries on what {@link #handOff}
     * returned: the same server session, its transaction where it was.
     *
     * @throws IllegalArgumentException when it is not a client of seclume's
     *         driver, or {@code state} is not a handed-off session
     */
    public static ClientSession takeUp(MongoClient client, byte[] state) {
        if (!(client instanceof SeclumeClient ours)) {
            throw new IllegalArgumentException("not a client of seclume's MongoDB driver");
        }
        if (state.length < 5 || ByteBuffer.wrap(state, 0, 4).order(ByteOrder.LITTLE_ENDIAN)
                .getInt() != state.length) {
            throw new IllegalArgumentException("not the state of a handed-off session");
        }
        try {
            BsonDocument document = new RawBsonDocument(state).decode(new BsonDocumentCodec());
            return ours.takeUp(LogicalSession.State.fromBson(document));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("not the state of a handed-off session", e);
        }
    }
}
