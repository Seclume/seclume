package space.seclume.mongodb.driver;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonMaximumSizeExceededException;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.codecs.Codec;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.conversions.Bson;

import com.mongodb.ClientBulkWriteException;
import com.mongodb.MongoClientException;
import com.mongodb.MongoException;
import com.mongodb.MongoNamespace;
import com.mongodb.ServerAddress;
import com.mongodb.WriteConcern;
import com.mongodb.WriteError;
import com.mongodb.bulk.WriteConcernError;
import com.mongodb.client.model.Collation;
import com.mongodb.client.model.bulk.ClientBulkWriteOptions;
import com.mongodb.client.model.bulk.ClientBulkWriteResult;
import com.mongodb.client.model.bulk.ClientDeleteResult;
import com.mongodb.client.model.bulk.ClientInsertOneResult;
import com.mongodb.client.model.bulk.ClientNamespacedWriteModel;
import com.mongodb.client.model.bulk.ClientUpdateResult;
import com.mongodb.internal.client.model.bulk.AbstractClientDeleteModel;
import com.mongodb.internal.client.model.bulk.AbstractClientNamespacedWriteModel;
import com.mongodb.internal.client.model.bulk.AbstractClientUpdateModel;
import com.mongodb.internal.client.model.bulk.ClientWriteModel;
import com.mongodb.internal.client.model.bulk.ConcreteClientBulkWriteOptions;
import com.mongodb.internal.client.model.bulk.ConcreteClientDeleteManyModel;
import com.mongodb.internal.client.model.bulk.ConcreteClientInsertOneModel;
import com.mongodb.internal.client.model.bulk.ConcreteClientReplaceOneModel;
import com.mongodb.internal.client.model.bulk.ConcreteClientUpdateManyModel;
import com.mongodb.internal.client.model.bulk.ConcreteClientUpdateOneOptions;

import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * The client-level bulkWrite (MongoDB 8): writes to any collections of any
 * databases in one command - the operations as the document sequence
 * {@code ops}, each naming its namespace by an index into {@code nsInfo}.
 * From the client bulk write specification (source/crud/bulk-write.md).
 *
 * <p>The models are public interfaces without getters; what they hold is in
 * the official driver's {@code com.mongodb.internal.client.model.bulk}
 * classes - the same in 5.8 (what Spring Boot manages) and 5.13. They are read
 * here and only here, and a model of another shape is refused by name.
 */
final class ClientBulkWrites {

    /** The wire version of MongoDB 8.0, which has the command. */
    private static final int MIN_WIRE_VERSION = 25;

    private ClientBulkWrites() {
    }

    /** One operation, as {@code ops} carries it, with what it needs for its result. */
    private record Op(BsonDocument statement, MongoNamespace namespace, BsonValue insertedId,
                      boolean multi) {
    }

    static ClientBulkWriteResult run(Topology topology, LogicalSession session,
            CodecRegistry registry, WriteConcern writeConcern,
            List<? extends ClientNamespacedWriteModel> models, ClientBulkWriteOptions given) {
        if (models.isEmpty()) {
            throw new IllegalArgumentException("bulkWrite needs at least one write");
        }
        int wire = topology.writableHello().getNumber("maxWireVersion", new BsonInt32(0))
                .intValue();
        if (wire < MIN_WIRE_VERSION) {
            throw new MongoClientException("the client-level bulkWrite needs MongoDB 8.0 or "
                    + "newer; the server speaks wire version " + wire);
        }
        ConcreteClientBulkWriteOptions options = (ConcreteClientBulkWriteOptions) (given == null
                ? ClientBulkWriteOptions.clientBulkWriteOptions() : given);
        List<Op> ops = new ArrayList<>(models.size());
        for (ClientNamespacedWriteModel model : models) {
            ops.add(op(model, registry));
        }
        int maxBatch = topology.writableHello().getNumber("maxWriteBatchSize",
                new BsonInt32(100_000)).intValue();
        boolean acknowledged = writeConcern == null || writeConcern.isAcknowledged();

        Summary summary = new Summary(options.isVerboseResults());
        Map<Integer, WriteError> writeErrors = new LinkedHashMap<>();
        List<WriteConcernError> concernErrors = new ArrayList<>();
        ServerAddress address = null;
        int at = 0;
        while (at < ops.size()) {
            int count = Math.min(maxBatch, ops.size() - at);
            while (true) {
                List<Op> batch = ops.subList(at, at + count);
                try {
                    BsonDocument command = command(batch, options, writeConcern, registry);
                    List<BsonDocument> statements = batch.stream().map(Op::statement).toList();
                    if (!acknowledged) {
                        topology.writeUnacknowledged(session, "admin", command, "ops", statements);
                        break;
                    }
                    boolean retryable = batch.stream().noneMatch(Op::multi);
                    Topology.Reply reply;
                    try {
                        reply = topology.write(session, "admin", command, "ops", statements,
                                retryable);
                    } catch (MongoException failed) {
                        if (at == 0) {
                            throw failed;                   // nothing went through: as it is
                        }
                        throw new ClientBulkWriteException(failed, concernErrors, writeErrors,
                                summary.partial(), address);
                    }
                    address = reply.server().address();
                    read(topology, session, reply, batch, at, summary, writeErrors, concernErrors);
                    break;
                } catch (BsonMaximumSizeExceededException tooLarge) {
                    if (count == 1) {
                        throw tooLarge;
                    }
                    count = (count + 1) / 2;
                }
            }
            at += count;
            if (options.isOrdered() && !writeErrors.isEmpty()) {
                break;
            }
        }
        if (!acknowledged) {
            return Summary.UNACKNOWLEDGED;
        }
        if (!writeErrors.isEmpty() || !concernErrors.isEmpty()) {
            throw new ClientBulkWriteException(null, concernErrors, writeErrors,
                    summary.partial(), address);
        }
        return summary.result();
    }

    private static BsonDocument command(List<Op> batch, ConcreteClientBulkWriteOptions options,
            WriteConcern writeConcern, CodecRegistry registry) {
        Map<MongoNamespace, Integer> namespaces = new LinkedHashMap<>();
        for (Op op : batch) {
            namespaces.putIfAbsent(op.namespace(), namespaces.size());
        }
        // Each op names its namespace by its index in this batch's nsInfo.
        for (Op op : batch) {
            String verb = op.statement().getFirstKey();
            op.statement().put(verb, new BsonInt32(namespaces.get(op.namespace())));
        }
        BsonArray nsInfo = new BsonArray();
        for (MongoNamespace namespace : namespaces.keySet()) {
            nsInfo.add(new BsonDocument("ns", new BsonString(namespace.getFullName())));
        }
        BsonDocument command = new BsonDocument("bulkWrite", new BsonInt32(1))
                .append("errorsOnly", BsonBoolean.valueOf(!options.isVerboseResults()))
                .append("ordered", BsonBoolean.valueOf(options.isOrdered()))
                .append("nsInfo", nsInfo);
        options.isBypassDocumentValidation().ifPresent(bypass ->
                command.put("bypassDocumentValidation", BsonBoolean.valueOf(bypass)));
        options.getComment().ifPresent(comment -> command.put("comment", comment));
        options.getLet().ifPresent(let -> command.put("let",
                Bsons.toDocument(let, BsonDocument.class, registry)));
        Bsons.writeConcern(command, writeConcern);
        return command;
    }

    /** The per-operation results - in a cursor, which may need getMore - and the counts. */
    private static void read(Topology topology, LogicalSession session, Topology.Reply reply,
            List<Op> batch, int offset, Summary summary, Map<Integer, WriteError> writeErrors,
            List<WriteConcernError> concernErrors) {
        BsonDocument document = reply.document();
        summary.add(document);
        if (document.containsKey("writeConcernError")) {
            BsonDocument error = document.getDocument("writeConcernError");
            concernErrors.add(new WriteConcernError(error.getNumber("code").intValue(),
                    error.getString("codeName", new BsonString("")).getValue(),
                    error.getString("errmsg", new BsonString("")).getValue(),
                    error.getDocument("errInfo", new BsonDocument())));
        }
        try (BatchCursor<BsonDocument> results = new BatchCursor<>(topology, reply, session,
                new org.bson.codecs.BsonDocumentCodec(), 0, 0, null)) {
            while (results.hasNext()) {
                BsonDocument result = results.next();
                int index = offset + result.getNumber("idx").intValue();
                Op op = batch.get(index - offset);
                if (result.getNumber("ok").doubleValue() != 1.0) {
                    writeErrors.put(index, new WriteError(result.getNumber("code").intValue(),
                            result.getString("errmsg", new BsonString("")).getValue(),
                            result.getDocument("errInfo", new BsonDocument())));
                    continue;
                }
                summary.verbose(index, op, result);
            }
        }
    }

    private static Op op(ClientNamespacedWriteModel given, CodecRegistry registry) {
        if (!(given instanceof AbstractClientNamespacedWriteModel model)) {
            throw new IllegalArgumentException("a write model of a shape this driver does not "
                    + "know: " + given.getClass().getName());
        }
        MongoNamespace namespace = model.getNamespace();
        ClientWriteModel inner = model.getModel();
        if (inner instanceof ConcreteClientInsertOneModel insert) {
            BsonDocument encoded = encode(insert.getDocument(), registry, true);
            return new Op(new BsonDocument("insert", new BsonInt32(0))
                    .append("document", encoded), namespace, encoded.get("_id"), false);
        }
        if (inner instanceof ConcreteClientReplaceOneModel replace) {
            BsonDocument replacement = encode(replace.getReplacement(), registry, false);
            Bsons.checkReplacement(replacement);
            BsonDocument statement = new BsonDocument("update", new BsonInt32(0))
                    .append("filter", filter(replace.getFilter(), registry))
                    .append("updateMods", replacement)
                    .append("multi", BsonBoolean.FALSE);
            var options = replace.getOptions();
            options.isUpsert().ifPresent(upsert -> statement.put("upsert",
                    BsonBoolean.valueOf(upsert)));
            common(statement, options.getHint(), options.getHintString(),
                    options.getCollation(), registry);
            options.getSort().ifPresent(sort -> statement.put("sort",
                    Bsons.toDocument(sort, BsonDocument.class, registry)));
            return new Op(statement, namespace, null, false);
        }
        if (inner instanceof AbstractClientUpdateModel<?> update) {
            boolean multi = inner instanceof ConcreteClientUpdateManyModel;
            BsonValue mods;
            if (update.getUpdatePipeline().isPresent()) {
                List<Bson> stages = new ArrayList<>();
                update.getUpdatePipeline().get().forEach(stages::add);
                mods = Bsons.toArray(stages, BsonDocument.class, registry);
            } else {
                BsonDocument operators = Bsons.toDocument(update.getUpdate().orElseThrow(),
                        BsonDocument.class, registry);
                Bsons.checkUpdate(operators);
                mods = operators;
            }
            BsonDocument statement = new BsonDocument("update", new BsonInt32(0))
                    .append("filter", filter(update.getFilter(), registry))
                    .append("updateMods", mods)
                    .append("multi", BsonBoolean.valueOf(multi));
            var options = update.getOptions();
            options.isUpsert().ifPresent(upsert -> statement.put("upsert",
                    BsonBoolean.valueOf(upsert)));
            options.getArrayFilters().ifPresent(filters -> {
                List<Bson> all = new ArrayList<>();
                filters.forEach(all::add);
                statement.put("arrayFilters", Bsons.toArray(all, BsonDocument.class, registry));
            });
            common(statement, options.getHint(), options.getHintString(),
                    options.getCollation(), registry);
            if (options instanceof ConcreteClientUpdateOneOptions one) {
                one.getSort().ifPresent(sort -> statement.put("sort",
                        Bsons.toDocument(sort, BsonDocument.class, registry)));
            }
            return new Op(statement, namespace, null, multi);
        }
        if (inner instanceof AbstractClientDeleteModel<?> delete) {
            boolean multi = inner instanceof ConcreteClientDeleteManyModel;
            BsonDocument statement = new BsonDocument("delete", new BsonInt32(0))
                    .append("filter", filter(delete.getFilter(), registry))
                    .append("multi", BsonBoolean.valueOf(multi));
            var options = delete.getOptions();
            common(statement, options.getHint(), options.getHintString(),
                    options.getCollation(), registry);
            return new Op(statement, namespace, null, multi);
        }
        throw new IllegalArgumentException("a write model of a shape this driver does not "
                + "know: " + inner.getClass().getName());
    }

    private static void common(BsonDocument statement, Optional<Bson> hint,
            Optional<String> hintString, Optional<Collation> collation, CodecRegistry registry) {
        Bsons.hint(statement, hint.orElse(null), hintString.orElse(null), BsonDocument.class,
                registry);
        collation.ifPresent(c -> statement.put("collation", c.asDocument()));
    }

    private static BsonDocument filter(Bson filter, CodecRegistry registry) {
        if (filter == null) {
            throw new IllegalArgumentException("the filter is null");
        }
        return Bsons.toDocument(filter, BsonDocument.class, registry);
    }

    @SuppressWarnings("unchecked")
    private static BsonDocument encode(Object document, CodecRegistry registry, boolean withId) {
        if (document == null) {
            throw new IllegalArgumentException("the document is null");
        }
        Codec<Object> codec = (Codec<Object>) registry.get(document.getClass());
        return Bsons.encode(document, codec, withId);
    }

    /** The counts, and with verboseResults each operation's result. */
    private static final class Summary {
        static final ClientBulkWriteResult UNACKNOWLEDGED = new Result(false, 0, 0, 0, 0, 0,
                null);

        private final boolean verbose;
        private long inserted;
        private long upserted;
        private long matched;
        private long modified;
        private long deleted;
        private final Map<Integer, ClientInsertOneResult> inserts = new LinkedHashMap<>();
        private final Map<Integer, ClientUpdateResult> updates = new LinkedHashMap<>();
        private final Map<Integer, ClientDeleteResult> deletes = new LinkedHashMap<>();

        Summary(boolean verbose) {
            this.verbose = verbose;
        }

        void add(BsonDocument reply) {
            inserted += count(reply, "nInserted");
            upserted += count(reply, "nUpserted");
            matched += count(reply, "nMatched");
            modified += count(reply, "nModified");
            deleted += count(reply, "nDeleted");
        }

        private static long count(BsonDocument reply, String name) {
            return reply.getNumber(name, new BsonInt64(0)).longValue();
        }

        void verbose(int index, Op op, BsonDocument result) {
            if (!verbose) {
                return;
            }
            switch (op.statement().getFirstKey()) {
                case "insert" -> inserts.put(index, () -> Optional.ofNullable(op.insertedId()));
                case "update" -> {
                    long n = result.getNumber("n", new BsonInt32(0)).longValue();
                    long nModified = result.getNumber("nModified", new BsonInt32(0)).longValue();
                    BsonValue id = result.containsKey("upserted")
                            ? result.getDocument("upserted").get("_id") : null;
                    long matchedHere = id == null ? n : 0;
                    updates.put(index, new UpdateResult(matchedHere, nModified, id));
                }
                default -> {
                    long n = result.getNumber("n", new BsonInt32(0)).longValue();
                    deletes.put(index, () -> n);
                }
            }
        }

        /** What went through, or null when nothing did - then there is no partial result. */
        ClientBulkWriteResult partial() {
            boolean any = inserted + upserted + matched + modified + deleted > 0
                    || !inserts.isEmpty() || !updates.isEmpty() || !deletes.isEmpty();
            return any ? result() : null;
        }

        ClientBulkWriteResult result() {
            return new Result(true, inserted, upserted, matched, modified, deleted,
                    verbose ? new Verbose(Map.copyOf(inserts), Map.copyOf(updates),
                            Map.copyOf(deletes)) : null);
        }
    }

    private record UpdateResult(long matched, long modified, BsonValue upsertedId)
            implements ClientUpdateResult {
        @Override
        public long getMatchedCount() {
            return matched;
        }

        @Override
        public long getModifiedCount() {
            return modified;
        }

        @Override
        public Optional<BsonValue> getUpsertedId() {
            return Optional.ofNullable(upsertedId);
        }
    }

    private record Verbose(Map<Integer, ClientInsertOneResult> inserts,
                           Map<Integer, ClientUpdateResult> updates,
                           Map<Integer, ClientDeleteResult> deletes)
            implements ClientBulkWriteResult.VerboseResults {
        @Override
        public Map<Integer, ClientInsertOneResult> getInsertResults() {
            return inserts;
        }

        @Override
        public Map<Integer, ClientUpdateResult> getUpdateResults() {
            return updates;
        }

        @Override
        public Map<Integer, ClientDeleteResult> getDeleteResults() {
            return deletes;
        }
    }

    private record Result(boolean acknowledged, long inserted, long upserted, long matched,
                          long modified, long deleted, Verbose verbose)
            implements ClientBulkWriteResult {
        private void needsAcknowledged() {
            if (!acknowledged) {
                throw new UnsupportedOperationException("the write was not acknowledged "
                        + "(w: 0): there are no counts");
            }
        }

        @Override
        public boolean isAcknowledged() {
            return acknowledged;
        }

        @Override
        public long getInsertedCount() {
            needsAcknowledged();
            return inserted;
        }

        @Override
        public long getUpsertedCount() {
            needsAcknowledged();
            return upserted;
        }

        @Override
        public long getMatchedCount() {
            needsAcknowledged();
            return matched;
        }

        @Override
        public long getModifiedCount() {
            needsAcknowledged();
            return modified;
        }

        @Override
        public long getDeletedCount() {
            needsAcknowledged();
            return deleted;
        }

        @Override
        public Optional<VerboseResults> getVerboseResults() {
            needsAcknowledged();
            return Optional.ofNullable(verbose);
        }
    }
}
