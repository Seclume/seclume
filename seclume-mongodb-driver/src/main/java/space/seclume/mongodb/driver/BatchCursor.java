package space.seclume.mongodb.driver;

import java.util.NoSuchElementException;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.codecs.Decoder;

import com.mongodb.MongoException;
import com.mongodb.ServerAddress;
import com.mongodb.ServerCursor;
import com.mongodb.client.MongoCursor;

import space.seclume.mongodb.driver.internal.Deadline;
import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.ServerPool;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * A server cursor read batch by batch: the first batch comes with the
 * command, the next ones with {@code getMore}, and a cursor given up before
 * its end is killed on the server ({@code killCursors}) so that it does not
 * stay open there until the server's ten-minute idle timeout.
 *
 * <p>A cursor is not tied to the connection that opened it, so each
 * {@code getMore} borrows whichever connection to its server is free - a
 * cursor lives on the server that opened it.
 */
final class BatchCursor<T> implements MongoCursor<T> {

    private final Topology topology;
    private final ServerPool server;
    private final LogicalSession session;
    private final Decoder<T> decoder;
    private final String database;
    private final String collection;
    private final int batchSize;
    private final long maxAwaitMillis;
    private final BsonValue comment;
    private long id;
    private BsonArray batch;
    /** A change stream's position after the last batch, when the server says it. */
    private BsonDocument postBatchResumeToken;
    /** CURSOR_LIFETIME: the end of the cursor's time; ITERATION: the time per batch. */
    private Long lifetimeEnd;
    private Long iterationMillis;
    private int at;

    /**
     * @param reply a command's reply with a {@code cursor} document
     * @param maxAwaitMillis for a tailable cursor that awaits data: how long a
     *                       {@code getMore} waits; 0 for the server's default
     */
    BatchCursor(Topology topology, Topology.Reply reply, LogicalSession session,
            Decoder<T> decoder, int batchSize, long maxAwaitMillis, BsonValue comment) {
        this.topology = topology;
        this.server = reply.server();
        this.session = session;
        this.decoder = decoder;
        this.batchSize = batchSize;
        this.maxAwaitMillis = maxAwaitMillis;
        this.comment = comment;
        BsonDocument cursor = reply.document().getDocument("cursor");
        this.id = cursor.getNumber("id").longValue();
        String namespace = cursor.getString("ns").getValue();
        int dot = namespace.indexOf('.');
        this.database = namespace.substring(0, dot);
        this.collection = namespace.substring(dot + 1);
        this.batch = cursor.getArray("firstBatch");
        this.postBatchResumeToken = cursor.getDocument("postBatchResumeToken", null);
        if (id != 0 && session != null && session.explicit()) {
            session.opened(this);
        }
    }

    /** {@code timeoutMS} as the iterable applies it; both null for none. */
    void timed(Long lifetimeEnd, Long iterationMillis) {
        this.lifetimeEnd = lifetimeEnd;
        this.iterationMillis = iterationMillis;
    }

    @Override
    public boolean hasNext() {
        while (at >= batch.size()) {
            if (id == 0) {
                return false;
            }
            getMore();
        }
        return true;
    }

    @Override
    public T next() {
        if (!hasNext()) {
            throw new NoSuchElementException("next() after the last document - hasNext() says whether there is one");
        }
        return Bsons.decode(batch.get(at++).asDocument(), decoder);
    }

    /** One {@code getMore} at most: for a tailable cursor, {@code null} when nothing came. */
    @Override
    public T tryNext() {
        if (at >= batch.size() && id != 0) {
            getMore();
        }
        return at < batch.size() ? Bsons.decode(batch.get(at++).asDocument(), decoder) : null;
    }

    BsonDocument postBatchResumeToken() {
        return postBatchResumeToken;
    }

    /** Whether the current batch is read to its end. */
    boolean batchDone() {
        return at >= batch.size();
    }

    @Override
    public int available() {
        return batch.size() - at;
    }

    private void getMore() {
        try (Deadline.Scope _ = lifetimeEnd != null ? Deadline.at(lifetimeEnd)
                : Deadline.enter(iterationMillis)) {
            Deadline.check("reading the next batch");
            getMoreNow();
        }
    }

    private void getMoreNow() {
        BsonDocument command = new BsonDocument("getMore", new BsonInt64(id))
                .append("collection", new BsonString(collection));
        if (batchSize > 0) {
            command.put("batchSize", new BsonInt32(batchSize));
        }
        if (maxAwaitMillis > 0) {
            command.put("maxTimeMS", new BsonInt64(maxAwaitMillis));
        }
        if (comment != null) {
            command.put("comment", comment);
        }
        BsonDocument reply;
        try {
            reply = topology.on(server, session, database, command);
        } catch (MongoException e) {
            id = 0;                        // a cursor the server refused is gone there
            throw e;
        }
        BsonDocument cursor = reply.getDocument("cursor");
        id = cursor.getNumber("id").longValue();
        batch = cursor.getArray("nextBatch");
        postBatchResumeToken = cursor.getDocument("postBatchResumeToken", null);
        at = 0;
        if (id == 0 && session != null) {
            session.ended(this);
        }
    }

    @Override
    public void close() {
        if (session != null) {
            session.ended(this);
        }
        if (id == 0) {
            return;
        }
        long open = id;
        id = 0;
        batch = new BsonArray();
        at = 0;
        try {
            topology.on(server, session, database, new BsonDocument("killCursors", new BsonString(collection))
                    .append("cursors", new BsonArray(java.util.List.of(new BsonInt64(open)))));
        } catch (MongoException | IllegalStateException ignored) {
            // the server ends the cursor after its idle timeout; nothing else to do
        }
    }

    @Override
    public ServerCursor getServerCursor() {
        return id == 0 ? null : new ServerCursor(id, server.address());
    }

    @Override
    public ServerAddress getServerAddress() {
        return server.address();
    }
}
