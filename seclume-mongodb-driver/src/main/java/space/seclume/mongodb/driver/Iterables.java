package space.seclume.mongodb.driver;

import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.Document;
import org.bson.codecs.Decoder;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.conversions.Bson;

import com.mongodb.CursorType;
import com.mongodb.ExplainVerbosity;
import com.mongodb.Function;
import com.mongodb.ServerAddress;
import com.mongodb.ServerCursor;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.DistinctIterable;
import com.mongodb.client.FindIterable;
import com.mongodb.client.ListCollectionNamesIterable;
import com.mongodb.client.ListCollectionsIterable;
import com.mongodb.client.ListDatabasesIterable;
import com.mongodb.client.ListIndexesIterable;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoIterable;
import com.mongodb.client.cursor.TimeoutMode;
import com.mongodb.client.model.Collation;

import com.mongodb.ReadPreference;

import space.seclume.mongodb.driver.internal.Deadline;
import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * The iterables of the API: each builds its command when it is iterated, so
 * that one iterable can be iterated again and sees the options set last.
 */
final class Iterables {

    private Iterables() {
    }

    /** An iterable with the {@code timeoutMS} of what made it. */
    static <I extends Base<?>> I timed(I iterable, Long timeoutMillis) {
        iterable.timeoutMillis = timeoutMillis;
        return iterable;
    }

    static ListCollectionNames timed(ListCollectionNames names, Long timeoutMillis) {
        names.collections.timeoutMillis = timeoutMillis;
        return names;
    }

    static long millis(long timeout, TimeUnit unit) {
        if (timeout < 0) {
            throw new IllegalArgumentException("a timeout cannot be negative: " + timeout);
        }
        return TimeUnit.MILLISECONDS.convert(timeout, unit);
    }

    static UnsupportedOperationException noTimeoutMode() {
        return new UnsupportedOperationException("timeoutMode (client-side operation "
                + "timeouts) is not supported by seclume's MongoDB driver yet");
    }

    /** What every iterable shares: running, first, into, map. */
    abstract static class Base<T> implements MongoIterable<T> {
        final Topology topology;
        final LogicalSession session;
        final ReadPreference preference;
        final Decoder<T> decoder;
        int batchSize;
        /** {@code timeoutMS}, and how it applies to the cursor: its lifetime or each batch. */
        Long timeoutMillis;
        TimeoutMode timeoutMode;

        Base(Topology topology, LogicalSession session, ReadPreference preference,
                Decoder<T> decoder) {
            this.topology = topology;
            this.session = session;
            this.preference = preference;
            this.decoder = decoder;
        }

        @Override
        public MongoCursor<T> cursor() {
            return iterator();
        }

        /** What the iterable runs to give its cursor; {@link #iterator} bounds it in time. */
        abstract MongoCursor<T> open();

        /** The default timeout mode: a tailable cursor's batches each, others' whole lifetime. */
        TimeoutMode defaultTimeoutMode() {
            return TimeoutMode.CURSOR_LIFETIME;
        }

        /** The timeout mode in force; refused without timeoutMS, as the specification says. */
        TimeoutMode mode() {
            if (timeoutMode != null && timeoutMillis == null) {
                throw new IllegalArgumentException("timeoutMode needs timeoutMS: set it on the "
                        + "client, the database or the collection");
            }
            return timeoutMode != null ? timeoutMode : defaultTimeoutMode();
        }

        @Override
        public final MongoCursor<T> iterator() {
            TimeoutMode mode = mode();
            try (Deadline.Scope _ = mode == TimeoutMode.ITERATION
                    ? Deadline.perBatch(timeoutMillis) : Deadline.enter(timeoutMillis)) {
                MongoCursor<T> cursor = open();
                if (cursor instanceof BatchCursor<T> batches && timeoutMillis != null
                        && timeoutMillis > 0) {
                    batches.timed(mode == TimeoutMode.CURSOR_LIFETIME ? Deadline.end() : null,
                            mode == TimeoutMode.ITERATION ? timeoutMillis : null);
                }
                return cursor;
            }
        }

        @Override
        public T first() {
            try (MongoCursor<T> cursor = firstOnly()) {
                return cursor.hasNext() ? cursor.next() : null;
            }
        }

        /** The cursor {@link #first} reads; a command that can ask for one document only does. */
        MongoCursor<T> firstOnly() {
            return iterator();
        }

        @Override
        public <U> MongoIterable<U> map(Function<T, U> mapper) {
            return new Mapped<>(this, mapper);
        }

        @Override
        public <A extends Collection<? super T>> A into(A target) {
            try (MongoCursor<T> cursor = iterator()) {
                while (cursor.hasNext()) {
                    target.add(cursor.next());
                }
            }
            return target;
        }

        @Override
        public MongoIterable<T> batchSize(int size) {
            this.batchSize = size;
            return this;
        }
    }

    /** A command that answers with a cursor. */
    abstract static class Command<T> extends Base<T> {
        final String database;
        BsonValue comment;
        long maxTimeMillis;

        Command(Topology topology, LogicalSession session, ReadPreference preference,
                Decoder<T> decoder, String database) {
            super(topology, session, preference, decoder);
            this.database = database;
        }

        abstract BsonDocument command();

        long maxAwaitMillis() {
            return 0;
        }

        @Override
        MongoCursor<T> open() {
            Topology.Reply reply = topology.read(session, preference, database, command());
            return new BatchCursor<>(topology, reply, session, decoder, batchSize,
                    maxAwaitMillis(), comment);
        }

        BsonDocument cursorOptions() {
            BsonDocument cursor = new BsonDocument();
            if (batchSize > 0) {
                cursor.put("batchSize", new BsonInt32(batchSize));
            }
            return cursor;
        }
    }

    /** An iterable over an array the reply holds whole, with no server cursor. */
    static final class ArrayCursor<T> implements MongoCursor<T> {
        private final BsonArray values;
        private final java.util.function.Function<BsonValue, T> decode;
        private final ServerAddress address;
        private int at;

        ArrayCursor(BsonArray values, java.util.function.Function<BsonValue, T> decode,
                ServerAddress address) {
            this.values = values;
            this.decode = decode;
            this.address = address;
        }

        @Override
        public boolean hasNext() {
            return at < values.size();
        }

        @Override
        public T next() {
            if (!hasNext()) {
                throw new NoSuchElementException("next() after the last result - hasNext() says whether there is one");
            }
            return decode.apply(values.get(at++));
        }

        @Override
        public T tryNext() {
            return hasNext() ? next() : null;
        }

        @Override
        public int available() {
            return values.size() - at;
        }

        @Override
        public ServerCursor getServerCursor() {
            return null;
        }

        @Override
        public ServerAddress getServerAddress() {
            return address;
        }

        @Override
        public void close() {
            at = values.size();
        }
    }

    static final class Mapped<T, U> implements MongoIterable<U> {
        private final MongoIterable<T> source;
        private final Function<T, U> mapper;

        Mapped(MongoIterable<T> source, Function<T, U> mapper) {
            this.source = source;
            this.mapper = mapper;
        }

        @Override
        public MongoCursor<U> iterator() {
            MongoCursor<T> cursor = source.iterator();
            return new MongoCursor<>() {
                @Override
                public void close() {
                    cursor.close();
                }

                @Override
                public boolean hasNext() {
                    return cursor.hasNext();
                }

                @Override
                public U next() {
                    return mapper.apply(cursor.next());
                }

                @Override
                public int available() {
                    return cursor.available();
                }

                @Override
                public U tryNext() {
                    T next = cursor.tryNext();
                    return next == null ? null : mapper.apply(next);
                }

                @Override
                public ServerCursor getServerCursor() {
                    return cursor.getServerCursor();
                }

                @Override
                public ServerAddress getServerAddress() {
                    return cursor.getServerAddress();
                }
            };
        }

        @Override
        public MongoCursor<U> cursor() {
            return iterator();
        }

        @Override
        public U first() {
            T first = source.first();
            return first == null ? null : mapper.apply(first);
        }

        @Override
        public <V> MongoIterable<V> map(Function<U, V> next) {
            return new Mapped<>(this, next);
        }

        @Override
        public <A extends Collection<? super U>> A into(A target) {
            try (MongoCursor<U> cursor = iterator()) {
                while (cursor.hasNext()) {
                    target.add(cursor.next());
                }
            }
            return target;
        }

        @Override
        public MongoIterable<U> batchSize(int size) {
            source.batchSize(size);
            return this;
        }
    }

    // ---- find ---------------------------------------------------------------

    static final class Find<T> extends Command<T> implements FindIterable<T> {
        private final String collection;
        private final Class<?> documentClass;
        private final CodecRegistry registry;
        private final Supplier<BsonDocument> readConcern;
        private Bson filter;
        private int limit;
        private int skip;
        private long maxAwaitMillis;
        private Bson projection;
        private Bson sort;
        private boolean noCursorTimeout;
        private boolean partial;
        private CursorType cursorType = CursorType.NonTailable;
        private Collation collation;
        private Bson hint;
        private String hintString;
        private Bson let;
        private Bson max;
        private Bson min;
        private boolean returnKey;
        private boolean showRecordId;
        private Boolean allowDiskUse;

        Find(Topology topology, LogicalSession session, ReadPreference preference,
                Decoder<T> decoder, String database, String collection,
                Class<?> documentClass, CodecRegistry registry, Bson filter,
                Supplier<BsonDocument> readConcern) {
            super(topology, session, preference, decoder, database);
            this.collection = collection;
            this.documentClass = documentClass;
            this.registry = registry;
            this.filter = filter;
            this.readConcern = readConcern;
        }

        @Override
        BsonDocument command() {
            return command(limit, false);
        }

        private BsonDocument command(int limit, boolean single) {
            BsonDocument command = new BsonDocument("find", new BsonString(collection));
            Bsons.put(command, "filter", filter, documentClass, registry);
            Bsons.put(command, "sort", sort, documentClass, registry);
            Bsons.put(command, "projection", projection, documentClass, registry);
            Bsons.hint(command, hint, hintString, documentClass, registry);
            if (skip > 0) {
                command.put("skip", new BsonInt32(skip));
            }
            if (limit < 0 || single) {
                command.put("limit", new BsonInt32(Math.abs(limit == 0 ? 1 : limit)));
                command.put("singleBatch", org.bson.BsonBoolean.TRUE);
            } else if (limit > 0) {
                command.put("limit", new BsonInt32(limit));
            }
            if (batchSize > 0) {
                command.put("batchSize", new BsonInt32(batchSize));
            }
            Bsons.put(command, "comment", comment);
            Bsons.maxTime(command, maxTimeMillis);
            Bsons.put(command, "max", max, documentClass, registry);
            Bsons.put(command, "min", min, documentClass, registry);
            Bsons.putTrue(command, "returnKey", returnKey);
            Bsons.putTrue(command, "showRecordId", showRecordId);
            Bsons.putTrue(command, "noCursorTimeout", noCursorTimeout);
            Bsons.putTrue(command, "allowPartialResults", partial);
            if (cursorType != CursorType.NonTailable) {
                command.put("tailable", org.bson.BsonBoolean.TRUE);
                if (cursorType == CursorType.TailableAwait) {
                    command.put("awaitData", org.bson.BsonBoolean.TRUE);
                }
            }
            Bsons.put(command, "collation", collation);
            Bsons.put(command, "allowDiskUse", allowDiskUse);
            Bsons.put(command, "let", let, documentClass, registry);
            BsonDocument concern = readConcern.get();
            if (concern != null) {
                command.put("readConcern", concern);
            }
            return command;
        }

        @Override
        MongoCursor<T> firstOnly() {
            // One document in one batch, and no cursor left open on the server.
            mode();
            try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
                return firstBatchOnly();
            }
        }

        private MongoCursor<T> firstBatchOnly() {
            Topology.Reply reply = topology.read(session, preference, database,
                    command(1, true));
            return new BatchCursor<>(topology, reply, session, decoder, 0, 0, comment);
        }

        @Override
        long maxAwaitMillis() {
            return maxAwaitMillis;
        }

        @Override
        TimeoutMode defaultTimeoutMode() {
            return cursorType == CursorType.NonTailable ? TimeoutMode.CURSOR_LIFETIME
                    : TimeoutMode.ITERATION;
        }

        @Override
        public FindIterable<T> filter(Bson filter) {
            this.filter = filter;
            return this;
        }

        @Override
        public FindIterable<T> limit(int limit) {
            this.limit = limit;
            return this;
        }

        @Override
        public FindIterable<T> skip(int skip) {
            this.skip = skip;
            return this;
        }

        @Override
        public FindIterable<T> maxTime(long maxTime, TimeUnit unit) {
            this.maxTimeMillis = Bsons.millis(maxTime, unit);
            return this;
        }

        @Override
        public FindIterable<T> maxAwaitTime(long maxAwaitTime, TimeUnit unit) {
            this.maxAwaitMillis = Bsons.millis(maxAwaitTime, unit);
            return this;
        }

        @Override
        public FindIterable<T> projection(Bson projection) {
            this.projection = projection;
            return this;
        }

        @Override
        public FindIterable<T> sort(Bson sort) {
            this.sort = sort;
            return this;
        }

        @Override
        public FindIterable<T> noCursorTimeout(boolean noCursorTimeout) {
            this.noCursorTimeout = noCursorTimeout;
            return this;
        }

        @Override
        public FindIterable<T> partial(boolean partial) {
            this.partial = partial;
            return this;
        }

        @Override
        public FindIterable<T> cursorType(CursorType cursorType) {
            this.cursorType = cursorType;
            return this;
        }

        @Override
        public FindIterable<T> batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        @Override
        public FindIterable<T> collation(Collation collation) {
            this.collation = collation;
            return this;
        }

        @Override
        public FindIterable<T> comment(String comment) {
            this.comment = comment == null ? null : new BsonString(comment);
            return this;
        }

        @Override
        public FindIterable<T> comment(BsonValue comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public FindIterable<T> hint(Bson hint) {
            this.hint = hint;
            return this;
        }

        @Override
        public FindIterable<T> hintString(String hint) {
            this.hintString = hint;
            return this;
        }

        @Override
        public FindIterable<T> let(Bson variables) {
            this.let = variables;
            return this;
        }

        @Override
        public FindIterable<T> max(Bson max) {
            this.max = max;
            return this;
        }

        @Override
        public FindIterable<T> min(Bson min) {
            this.min = min;
            return this;
        }

        @Override
        public FindIterable<T> returnKey(boolean returnKey) {
            this.returnKey = returnKey;
            return this;
        }

        @Override
        public FindIterable<T> showRecordId(boolean showRecordId) {
            this.showRecordId = showRecordId;
            return this;
        }

        @Override
        public FindIterable<T> allowDiskUse(Boolean allowDiskUse) {
            this.allowDiskUse = allowDiskUse;
            return this;
        }

        @Override
        public FindIterable<T> timeoutMode(TimeoutMode timeoutMode) {
            this.timeoutMode = timeoutMode;
            return this;
        }

        @Override
        public Document explain() {
            return explain(Document.class, null);
        }

        @Override
        public Document explain(ExplainVerbosity verbosity) {
            return explain(Document.class, verbosity);
        }

        @Override
        public <E> E explain(Class<E> type) {
            return explain(type, null);
        }

        @Override
        public <E> E explain(Class<E> type, ExplainVerbosity verbosity) {
            try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
                return Explain.run(topology, session, preference, database, command(),
                        verbosity, registry.get(type));
            }
        }
    }

    /** {@code explain} around a read command. */
    static final class Explain {
        private Explain() {
        }

        static <E> E run(Topology topology, LogicalSession session, ReadPreference preference,
                String database, BsonDocument command, ExplainVerbosity verbosity,
                Decoder<E> decoder) {
            BsonDocument explain = new BsonDocument("explain", command);
            if (verbosity != null) {
                explain.put("verbosity", new BsonString(switch (verbosity) {
                    case QUERY_PLANNER -> "queryPlanner";
                    case EXECUTION_STATS -> "executionStats";
                    case ALL_PLANS_EXECUTIONS -> "allPlansExecution";
                }));
            }
            return Bsons.decode(topology.read(session, preference, database, explain)
                    .document(), decoder);
        }
    }

    // ---- aggregate ----------------------------------------------------------

    static final class Aggregate<T> extends Command<T> implements AggregateIterable<T> {
        private final BsonValue target;            // a collection's name, or 1 for a database
        private final List<? extends Bson> pipeline;
        private final Class<?> documentClass;
        private final CodecRegistry registry;
        private final Supplier<BsonDocument> readConcern;
        private final Supplier<BsonDocument> writeConcern;
        private Boolean allowDiskUse;
        private long maxAwaitMillis;
        private Boolean bypassDocumentValidation;
        private Collation collation;
        private Bson hint;
        private String hintString;
        private Bson let;

        Aggregate(Topology topology, LogicalSession session, ReadPreference preference,
                Decoder<T> decoder, String database, BsonValue target,
                List<? extends Bson> pipeline, Class<?> documentClass, CodecRegistry registry,
                Supplier<BsonDocument> readConcern, Supplier<BsonDocument> writeConcern) {
            super(topology, session, preference, decoder, database);
            this.target = target;
            this.pipeline = pipeline;
            this.documentClass = documentClass;
            this.registry = registry;
            this.readConcern = readConcern;
            this.writeConcern = writeConcern;
        }

        private BsonArray stages() {
            return Bsons.toArray(pipeline, documentClass, registry);
        }

        @Override
        BsonDocument command() {
            return command(stages(), cursorOptions());
        }

        private BsonDocument command(BsonArray stages, BsonDocument cursor) {
            BsonDocument command = new BsonDocument("aggregate", target)
                    .append("pipeline", stages)
                    .append("cursor", cursor);
            Bsons.put(command, "allowDiskUse", allowDiskUse);
            Bsons.maxTime(command, maxTimeMillis);
            Bsons.put(command, "bypassDocumentValidation", bypassDocumentValidation);
            Bsons.put(command, "collation", collation);
            Bsons.put(command, "comment", comment);
            Bsons.hint(command, hint, hintString, documentClass, registry);
            Bsons.put(command, "let", let, documentClass, registry);
            if (writes(stages)) {
                BsonDocument concern = writeConcern.get();
                if (concern != null) {
                    command.put("writeConcern", concern);
                }
            } else {
                BsonDocument concern = readConcern.get();
                if (concern != null) {
                    command.put("readConcern", concern);
                }
            }
            return command;
        }

        private static boolean writes(BsonArray stages) {
            if (stages.isEmpty()) {
                return false;
            }
            String last = stages.get(stages.size() - 1).asDocument().getFirstKey();
            return last.equals("$out") || last.equals("$merge");
        }

        @Override
        long maxAwaitMillis() {
            return maxAwaitMillis;
        }

        /**
         * With {@code $out} or {@code $merge} last, the pipeline writes and the
         * results are what it wrote: they are read from the target afterwards,
         * as the official driver does.
         */
        @Override
        MongoCursor<T> open() {
            BsonArray stages = stages();
            if (!writes(stages)) {
                return super.open();
            }
            topology.write(session, database, command(stages, new BsonDocument()), null, null,
                    false);
            String[] written = writtenTo(stages);
            BsonDocument find = new BsonDocument("find", new BsonString(written[1]));
            if (batchSize > 0) {
                find.put("batchSize", new BsonInt32(batchSize));
            }
            Topology.Reply reply = topology.read(session, ReadPreference.primary(), written[0],
                    find);
            return new BatchCursor<>(topology, reply, session, decoder, batchSize, 0, null);
        }

        private String[] writtenTo(BsonArray stages) {
            BsonDocument last = stages.get(stages.size() - 1).asDocument();
            BsonValue to = last.containsKey("$out") ? last.get("$out")
                    : last.getDocument("$merge").get("into");
            if (to.isString()) {
                return new String[] {database, to.asString().getValue()};
            }
            BsonDocument named = to.asDocument();
            return new String[] {named.getString("db", new BsonString(database)).getValue(),
                    named.getString("coll").getValue()};
        }

        @Override
        public void toCollection() {
            try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
                writeToCollection();
            }
        }

        private void writeToCollection() {
            BsonArray stages = stages();
            if (!writes(stages)) {
                throw new IllegalStateException("toCollection needs $out or $merge as the "
                        + "last stage of the pipeline");
            }
            topology.write(session, database, command(stages, new BsonDocument()), null, null,
                    false);
        }

        @Override
        public MongoCursor<T> cursor() {
            return iterator();
        }

        @Override
        public AggregateIterable<T> allowDiskUse(Boolean allowDiskUse) {
            this.allowDiskUse = allowDiskUse;
            return this;
        }

        @Override
        public AggregateIterable<T> batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        @Override
        public AggregateIterable<T> timeoutMode(TimeoutMode timeoutMode) {
            this.timeoutMode = timeoutMode;
            return this;
        }

        @Override
        public AggregateIterable<T> maxTime(long maxTime, TimeUnit unit) {
            this.maxTimeMillis = Bsons.millis(maxTime, unit);
            return this;
        }

        @Override
        public AggregateIterable<T> maxAwaitTime(long maxAwaitTime, TimeUnit unit) {
            this.maxAwaitMillis = Bsons.millis(maxAwaitTime, unit);
            return this;
        }

        @Override
        public AggregateIterable<T> bypassDocumentValidation(Boolean bypass) {
            this.bypassDocumentValidation = bypass;
            return this;
        }

        @Override
        public AggregateIterable<T> collation(Collation collation) {
            this.collation = collation;
            return this;
        }

        @Override
        public AggregateIterable<T> comment(String comment) {
            this.comment = comment == null ? null : new BsonString(comment);
            return this;
        }

        @Override
        public AggregateIterable<T> comment(BsonValue comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public AggregateIterable<T> hint(Bson hint) {
            this.hint = hint;
            return this;
        }

        @Override
        public AggregateIterable<T> hintString(String hint) {
            this.hintString = hint;
            return this;
        }

        @Override
        public AggregateIterable<T> let(Bson variables) {
            this.let = variables;
            return this;
        }

        @Override
        public Document explain() {
            return explain(Document.class, null);
        }

        @Override
        public Document explain(ExplainVerbosity verbosity) {
            return explain(Document.class, verbosity);
        }

        @Override
        public <E> E explain(Class<E> type) {
            return explain(type, null);
        }

        @Override
        public <E> E explain(Class<E> type, ExplainVerbosity verbosity) {
            BsonDocument command = command();
            command.remove("writeConcern");
            try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
                return Explain.run(topology, session, preference, database, command, verbosity,
                        registry.get(type));
            }
        }
    }

    // ---- distinct -----------------------------------------------------------

    static final class Distinct<T> extends Base<T> implements DistinctIterable<T> {
        private final String database;
        private final String collection;
        private final String field;
        private final Class<?> documentClass;
        private final CodecRegistry registry;
        private final Supplier<BsonDocument> readConcern;
        private Bson filter;
        private long maxTimeMillis;
        private Collation collation;
        private BsonValue comment;
        private Bson hint;
        private String hintString;

        Distinct(Topology topology, LogicalSession session, ReadPreference preference,
                Decoder<T> decoder, String database, String collection,
                String field, Bson filter, Class<?> documentClass, CodecRegistry registry,
                Supplier<BsonDocument> readConcern) {
            super(topology, session, preference, decoder);
            this.database = database;
            this.collection = collection;
            this.field = field;
            this.filter = filter;
            this.documentClass = documentClass;
            this.registry = registry;
            this.readConcern = readConcern;
        }

        @Override
        MongoCursor<T> open() {
            BsonDocument command = new BsonDocument("distinct", new BsonString(collection))
                    .append("key", new BsonString(field));
            Bsons.put(command, "query", filter, documentClass, registry);
            Bsons.maxTime(command, maxTimeMillis);
            Bsons.put(command, "collation", collation);
            Bsons.put(command, "comment", comment);
            Bsons.hint(command, hint, hintString, documentClass, registry);
            BsonDocument concern = readConcern.get();
            if (concern != null) {
                command.put("readConcern", concern);
            }
            Topology.Reply reply = topology.read(session, preference, database, command);
            BsonArray values = reply.document().getArray("values");
            // Each value is decoded as the one field of a document, so that the
            // application's codec for the type does the decoding.
            return new ArrayCursor<>(values, value -> Bsons.decode(
                    new BsonDocument("v", value), new ValueDecoder<>(decoder)),
                    reply.server().address());
        }

        @Override
        public DistinctIterable<T> filter(Bson filter) {
            this.filter = filter;
            return this;
        }

        @Override
        public DistinctIterable<T> maxTime(long maxTime, TimeUnit unit) {
            this.maxTimeMillis = Bsons.millis(maxTime, unit);
            return this;
        }

        @Override
        public DistinctIterable<T> batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        @Override
        public DistinctIterable<T> collation(Collation collation) {
            this.collation = collation;
            return this;
        }

        @Override
        public DistinctIterable<T> comment(String comment) {
            this.comment = comment == null ? null : new BsonString(comment);
            return this;
        }

        @Override
        public DistinctIterable<T> comment(BsonValue comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public DistinctIterable<T> hint(Bson hint) {
            this.hint = hint;
            return this;
        }

        @Override
        public DistinctIterable<T> hintString(String hint) {
            this.hintString = hint;
            return this;
        }

        @Override
        public DistinctIterable<T> timeoutMode(TimeoutMode timeoutMode) {
            this.timeoutMode = timeoutMode;
            return this;
        }
    }

    /** Reads the single field {@code v} of a document with the decoder of its value. */
    static final class ValueDecoder<T> implements Decoder<T> {
        private final Decoder<T> value;

        ValueDecoder(Decoder<T> value) {
            this.value = value;
        }

        @Override
        public T decode(org.bson.BsonReader reader, org.bson.codecs.DecoderContext context) {
            reader.readStartDocument();
            reader.readName();
            T decoded = reader.getCurrentBsonType() == org.bson.BsonType.NULL
                    ? readNull(reader) : context.decodeWithChildContext(value, reader);
            reader.readEndDocument();
            return decoded;
        }

        private static <T> T readNull(org.bson.BsonReader reader) {
            reader.readNull();
            return null;
        }
    }

    // ---- listing ------------------------------------------------------------

    static final class ListCollections<T> extends Command<T>
            implements ListCollectionsIterable<T> {
        private final boolean nameOnly;
        private final CodecRegistry registry;
        Bson filter;
        Boolean authorizedCollections;

        ListCollections(Topology topology, LogicalSession session, Decoder<T> decoder,
                String database, boolean nameOnly, CodecRegistry registry) {
            super(topology, session, ReadPreference.primary(), decoder, database);
            this.nameOnly = nameOnly;
            this.registry = registry;
        }

        @Override
        BsonDocument command() {
            BsonDocument command = new BsonDocument("listCollections", new BsonInt32(1))
                    .append("cursor", cursorOptions());
            Bsons.put(command, "filter", filter, BsonDocument.class, registry);
            Bsons.putTrue(command, "nameOnly", nameOnly);
            Bsons.put(command, "authorizedCollections", authorizedCollections);
            Bsons.maxTime(command, maxTimeMillis);
            Bsons.put(command, "comment", comment);
            return command;
        }

        @Override
        public ListCollectionsIterable<T> filter(Bson filter) {
            this.filter = filter;
            return this;
        }

        @Override
        public ListCollectionsIterable<T> maxTime(long maxTime, TimeUnit unit) {
            this.maxTimeMillis = Bsons.millis(maxTime, unit);
            return this;
        }

        @Override
        public ListCollectionsIterable<T> batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        @Override
        public ListCollectionsIterable<T> comment(String comment) {
            this.comment = comment == null ? null : new BsonString(comment);
            return this;
        }

        @Override
        public ListCollectionsIterable<T> comment(BsonValue comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public ListCollectionsIterable<T> timeoutMode(TimeoutMode timeoutMode) {
            this.timeoutMode = timeoutMode;
            return this;
        }
    }

    static final class ListCollectionNames implements ListCollectionNamesIterable {
        final ListCollections<BsonDocument> collections;

        ListCollectionNames(Topology topology, LogicalSession session, String database,
                CodecRegistry registry) {
            this.collections = new ListCollections<>(topology, session,
                    registry.get(BsonDocument.class), database, true, registry);
        }

        private MongoIterable<String> names() {
            return collections.map(collection -> collection.getString("name").getValue());
        }

        @Override
        public MongoCursor<String> iterator() {
            return names().iterator();
        }

        @Override
        public MongoCursor<String> cursor() {
            return iterator();
        }

        @Override
        public String first() {
            return names().first();
        }

        @Override
        public <U> MongoIterable<U> map(Function<String, U> mapper) {
            return names().map(mapper);
        }

        @Override
        public <A extends Collection<? super String>> A into(A target) {
            return names().into(target);
        }

        @Override
        public ListCollectionNamesIterable filter(Bson filter) {
            collections.filter(filter);
            return this;
        }

        @Override
        public ListCollectionNamesIterable maxTime(long maxTime, TimeUnit unit) {
            collections.maxTime(maxTime, unit);
            return this;
        }

        @Override
        public ListCollectionNamesIterable batchSize(int batchSize) {
            collections.batchSize(batchSize);
            return this;
        }

        @Override
        public ListCollectionNamesIterable comment(String comment) {
            collections.comment(comment);
            return this;
        }

        @Override
        public ListCollectionNamesIterable comment(BsonValue comment) {
            collections.comment(comment);
            return this;
        }

        @Override
        public ListCollectionNamesIterable authorizedCollections(boolean authorized) {
            collections.authorizedCollections = authorized;
            return this;
        }
    }

    /**
     * {@code $listSearchIndexes}: an aggregation of one stage, as the
     * index management specification has it - on Atlas, or a server with
     * {@code mongot} beside it.
     */
    static final class ListSearchIndexes<T> extends Command<T>
            implements com.mongodb.client.ListSearchIndexesIterable<T> {
        private final String collection;
        private final CodecRegistry registry;
        private String name;
        private Boolean allowDiskUse;
        private Collation collation;

        ListSearchIndexes(Topology topology, LogicalSession session, Decoder<T> decoder,
                String database, String collection, CodecRegistry registry) {
            super(topology, session, ReadPreference.primary(), decoder, database);
            this.collection = collection;
            this.registry = registry;
        }

        @Override
        BsonDocument command() {
            BsonDocument stage = new BsonDocument();
            if (name != null) {
                stage.put("name", new BsonString(name));
            }
            BsonDocument command = new BsonDocument("aggregate", new BsonString(collection))
                    .append("pipeline", new BsonArray(List.of(
                            new BsonDocument("$listSearchIndexes", stage))))
                    .append("cursor", cursorOptions());
            Bsons.put(command, "allowDiskUse", allowDiskUse);
            Bsons.maxTime(command, maxTimeMillis);
            Bsons.put(command, "collation", collation);
            Bsons.put(command, "comment", comment);
            return command;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> name(String indexName) {
            this.name = indexName;
            return this;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> allowDiskUse(Boolean allow) {
            this.allowDiskUse = allow;
            return this;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> batchSize(int size) {
            this.batchSize = size;
            return this;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> maxTime(long maxTime,
                TimeUnit unit) {
            this.maxTimeMillis = Bsons.millis(maxTime, unit);
            return this;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> collation(Collation value) {
            this.collation = value;
            return this;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> comment(String value) {
            this.comment = value == null ? null : new BsonString(value);
            return this;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> comment(BsonValue value) {
            this.comment = value;
            return this;
        }

        @Override
        public com.mongodb.client.ListSearchIndexesIterable<T> timeoutMode(TimeoutMode mode) {
            this.timeoutMode = mode;
            return this;
        }

        @Override
        public Document explain() {
            return explain(Document.class, null);
        }

        @Override
        public Document explain(ExplainVerbosity verbosity) {
            return explain(Document.class, verbosity);
        }

        @Override
        public <E> E explain(Class<E> type) {
            return explain(type, null);
        }

        @Override
        public <E> E explain(Class<E> type, ExplainVerbosity verbosity) {
            try (Deadline.Scope _ = Deadline.enter(timeoutMillis)) {
                return Explain.run(topology, session, preference, database, command(),
                        verbosity, registry.get(type));
            }
        }
    }

    static final class ListIndexes<T> extends Command<T> implements ListIndexesIterable<T> {
        private final String collection;

        ListIndexes(Topology topology, LogicalSession session, Decoder<T> decoder,
                String database, String collection) {
            super(topology, session, ReadPreference.primary(), decoder, database);
            this.collection = collection;
        }

        /**
         * A collection that is not there has no indexes - an empty cursor,
         * as the official driver answers, not the server's NamespaceNotFound.
         * GridFS asks before its first upload, and failed on it.
         */
        @Override
        MongoCursor<T> open() {
            try {
                return super.open();
            } catch (com.mongodb.MongoCommandException e) {
                if (e.getErrorCode() != 26) {
                    throw e;
                }
                return new ArrayCursor<>(new BsonArray(), value -> null, e.getServerAddress());
            }
        }

        @Override
        BsonDocument command() {
            BsonDocument command = new BsonDocument("listIndexes", new BsonString(collection))
                    .append("cursor", cursorOptions());
            Bsons.maxTime(command, maxTimeMillis);
            Bsons.put(command, "comment", comment);
            return command;
        }

        @Override
        public ListIndexesIterable<T> maxTime(long maxTime, TimeUnit unit) {
            this.maxTimeMillis = Bsons.millis(maxTime, unit);
            return this;
        }

        @Override
        public ListIndexesIterable<T> batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        @Override
        public ListIndexesIterable<T> comment(String comment) {
            this.comment = comment == null ? null : new BsonString(comment);
            return this;
        }

        @Override
        public ListIndexesIterable<T> comment(BsonValue comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public ListIndexesIterable<T> timeoutMode(TimeoutMode timeoutMode) {
            this.timeoutMode = timeoutMode;
            return this;
        }
    }

    static final class ListDatabases<T> extends Base<T> implements ListDatabasesIterable<T> {
        private final CodecRegistry registry;
        private final boolean namesOnly;
        private long maxTimeMillis;
        private Bson filter;
        private Boolean nameOnly;
        private Boolean authorizedDatabasesOnly;
        private BsonValue comment;

        ListDatabases(Topology topology, LogicalSession session, Decoder<T> decoder,
                CodecRegistry registry, boolean namesOnly) {
            super(topology, session, ReadPreference.primary(), decoder);
            this.registry = registry;
            this.namesOnly = namesOnly;
        }

        @Override
        MongoCursor<T> open() {
            BsonDocument command = new BsonDocument("listDatabases", new BsonInt32(1));
            Bsons.maxTime(command, maxTimeMillis);
            Bsons.put(command, "filter", filter, BsonDocument.class, registry);
            Bsons.put(command, "nameOnly", namesOnly ? Boolean.TRUE : nameOnly);
            Bsons.put(command, "authorizedDatabases", authorizedDatabasesOnly);
            Bsons.put(command, "comment", comment);
            Topology.Reply reply = topology.read(session, preference, "admin", command);
            BsonArray databases = reply.document().getArray("databases");
            return new ArrayCursor<>(databases,
                    value -> Bsons.decode(value.asDocument(), decoder), reply.server().address());
        }

        @Override
        public ListDatabasesIterable<T> maxTime(long maxTime, TimeUnit unit) {
            this.maxTimeMillis = Bsons.millis(maxTime, unit);
            return this;
        }

        @Override
        public ListDatabasesIterable<T> batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        @Override
        public ListDatabasesIterable<T> filter(Bson filter) {
            this.filter = filter;
            return this;
        }

        @Override
        public ListDatabasesIterable<T> nameOnly(Boolean nameOnly) {
            this.nameOnly = nameOnly;
            return this;
        }

        @Override
        public ListDatabasesIterable<T> authorizedDatabasesOnly(Boolean authorized) {
            this.authorizedDatabasesOnly = authorized;
            return this;
        }

        @Override
        public ListDatabasesIterable<T> comment(String comment) {
            this.comment = comment == null ? null : new BsonString(comment);
            return this;
        }

        @Override
        public ListDatabasesIterable<T> comment(BsonValue comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public ListDatabasesIterable<T> timeoutMode(TimeoutMode timeoutMode) {
            this.timeoutMode = timeoutMode;
            return this;
        }
    }
}
