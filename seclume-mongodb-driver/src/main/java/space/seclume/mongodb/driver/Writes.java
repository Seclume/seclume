package space.seclume.mongodb.driver;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bson.BsonDocument;
import org.bson.BsonMaximumSizeExceededException;
import org.bson.BsonString;
import org.bson.BsonValue;

import com.mongodb.MongoBulkWriteException;
import com.mongodb.MongoWriteConcernException;
import com.mongodb.MongoWriteException;
import com.mongodb.WriteConcernResult;
import com.mongodb.WriteError;
import com.mongodb.bulk.BulkWriteError;
import com.mongodb.bulk.BulkWriteInsert;
import com.mongodb.bulk.BulkWriteResult;
import com.mongodb.bulk.BulkWriteUpsert;
import com.mongodb.bulk.WriteConcernError;

import com.mongodb.ServerAddress;

import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * The write commands - {@code insert}, {@code update}, {@code delete} - in
 * batches the server takes, and what their replies say went wrong.
 *
 * <p>A write the server refused is not {@code ok: 0}: the command succeeds
 * and lists {@code writeErrors} and a {@code writeConcernError}, so each reply
 * is read for them. A single write reports as {@link MongoWriteException} or
 * {@link MongoWriteConcernException}, several as
 * {@link MongoBulkWriteException} with what got through - as the official
 * driver does, so that an application's error handling stays as it is.
 */
final class Writes {

    private Writes() {
    }

    /** One kind of write in batches; the counts summed, errors with their index in all of it. */
    static final class Outcome {
        int n;
        int modified;
        final List<BulkWriteUpsert> upserts = new ArrayList<>();
        final List<BulkWriteError> errors = new ArrayList<>();
        WriteConcernError concernError;
        final Set<String> labels = new HashSet<>();
        BsonValue upsertedId;
        ServerAddress address;
    }

    /**
     * Sends {@code items} as the document sequence {@code field} of
     * {@code command}, in as many commands as the server's limits need.
     *
     * @param offset the index of the first item in the whole operation
     */
    static Outcome run(Topology topology, LogicalSession session, String database,
            BsonDocument command, String field, List<BsonDocument> items, boolean ordered,
            boolean retryable, int offset, Outcome into) {
        int maxBatch = topology.writableHello().getNumber("maxWriteBatchSize",
                new org.bson.BsonInt32(100_000)).intValue();
        boolean acknowledged = !command.containsKey("writeConcern")
                || !command.getDocument("writeConcern").getNumber("w", new org.bson.BsonInt32(1))
                        .equals(new org.bson.BsonInt32(0));
        int at = 0;
        while (at < items.size()) {
            int count = Math.min(items.size() - at, maxBatch);
            if (!acknowledged) {
                // Unordered or not, nothing comes back to stop at: each batch goes.
                int sent = count;
                while (true) {
                    try {
                        topology.writeUnacknowledged(session, database, command, field,
                                items.subList(at, at + sent));
                        break;
                    } catch (BsonMaximumSizeExceededException tooLarge) {
                        if (sent == 1) {
                            throw tooLarge;
                        }
                        sent = (sent + 1) / 2;
                    }
                }
                at += sent;
                continue;
            }
            BsonDocument reply = null;
            while (reply == null) {
                try {
                    Topology.Reply sent = topology.write(session, database, command, field,
                            items.subList(at, at + count), retryable);
                    into.address = sent.server().address();
                    reply = sent.document();
                } catch (BsonMaximumSizeExceededException tooLarge) {
                    if (count == 1) {
                        throw tooLarge;            // one document alone too large: the server's limit
                    }
                    count = (count + 1) / 2;
                }
            }
            read(reply, offset + at, into);
            at += count;
            if (ordered && !into.errors.isEmpty()) {
                break;
            }
        }
        return into;
    }

    static void read(BsonDocument reply, int offset, Outcome into) {
        into.n += reply.getNumber("n", new org.bson.BsonInt32(0)).intValue();
        into.modified += reply.getNumber("nModified", new org.bson.BsonInt32(0)).intValue();
        if (reply.containsKey("upserted")) {
            for (BsonValue upsert : reply.getArray("upserted")) {
                BsonDocument one = upsert.asDocument();
                into.upserts.add(new BulkWriteUpsert(offset + one.getNumber("index").intValue(),
                        one.get("_id")));
                into.upsertedId = one.get("_id");
            }
        }
        if (reply.containsKey("writeErrors")) {
            for (BsonValue error : reply.getArray("writeErrors")) {
                BsonDocument one = error.asDocument();
                into.errors.add(new BulkWriteError(one.getNumber("code").intValue(),
                        one.getString("errmsg", new BsonString("")).getValue(),
                        one.getDocument("errInfo", new BsonDocument()),
                        offset + one.getNumber("index").intValue()));
            }
        }
        if (reply.containsKey("writeConcernError")) {
            BsonDocument error = reply.getDocument("writeConcernError");
            into.concernError = new WriteConcernError(error.getNumber("code").intValue(),
                    error.getString("codeName", new BsonString("")).getValue(),
                    error.getString("errmsg", new BsonString("")).getValue(),
                    error.getDocument("errInfo", new BsonDocument()));
            labels(error, into.labels);
        }
        labels(reply, into.labels);
    }

    private static void labels(BsonDocument document, Set<String> into) {
        if (document.containsKey("errorLabels")) {
            for (BsonValue label : document.getArray("errorLabels")) {
                into.add(label.asString().getValue());
            }
        }
    }

    /** For one write: its error as the single-write exceptions. */
    static void throwSingle(Outcome outcome, boolean update) {
        if (!outcome.errors.isEmpty()) {
            BulkWriteError error = outcome.errors.get(0);
            throw new MongoWriteException(new WriteError(error.getCode(), error.getMessage(),
                    error.getDetails()), outcome.address, outcome.labels);
        }
        if (outcome.concernError != null) {
            boolean existing = update && outcome.n > 0 && outcome.upserts.isEmpty();
            throw new MongoWriteConcernException(outcome.concernError,
                    WriteConcernResult.acknowledged(outcome.n, existing, outcome.upsertedId),
                    outcome.address, outcome.labels);
        }
    }

    /** For several: what got through and what did not. */
    static void throwBulk(Outcome outcome, BulkWriteResult partial) {
        if (!outcome.errors.isEmpty() || outcome.concernError != null) {
            throw new MongoBulkWriteException(partial, outcome.errors, outcome.concernError,
                    outcome.address, outcome.labels);
        }
    }

    static BulkWriteResult result(int inserted, int matched, int deleted, int modified,
            List<BulkWriteUpsert> upserts, List<BulkWriteInsert> inserts) {
        return BulkWriteResult.acknowledged(inserted, matched, deleted, modified, upserts,
                inserts);
    }
}
