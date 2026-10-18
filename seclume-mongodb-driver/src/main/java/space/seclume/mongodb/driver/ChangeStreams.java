package space.seclume.mongodb.driver;

import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonDocumentReader;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.bson.BsonTimestamp;
import org.bson.BsonValue;
import org.bson.codecs.BsonDocumentCodec;
import org.bson.codecs.Decoder;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.conversions.Bson;

import com.mongodb.Function;
import com.mongodb.MongoChangeStreamException;
import com.mongodb.MongoCommandException;
import com.mongodb.MongoException;
import com.mongodb.MongoSocketException;
import com.mongodb.ReadPreference;
import com.mongodb.ServerAddress;
import com.mongodb.ServerCursor;
import com.mongodb.client.ChangeStreamIterable;
import com.mongodb.client.MongoChangeStreamCursor;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoIterable;
import com.mongodb.client.model.Collation;
import com.mongodb.client.model.changestream.ChangeStreamDocument;
import com.mongodb.client.model.changestream.FullDocument;
import com.mongodb.client.model.changestream.FullDocumentBeforeChange;

import space.seclume.mongodb.driver.internal.Deadline;
import space.seclume.mongodb.driver.internal.LogicalSession;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * Change streams: an aggregation that begins with {@code $changeStream}, on a
 * collection, a database or the whole cluster, read through a tailable cursor
 * that waits for events.
 *
 * <p>What makes it more than a cursor is the resume token. The cursor keeps
 * the position of the last event it handed out - or the server's
 * {@code postBatchResumeToken} after a batch - and when the stream breaks on
 * an error the change streams specification calls resumable (a network
 * error, CursorNotFound, an error the server labels
 * {@code ResumableChangeStreamError}: a primary that stepped down, say), it
 * opens the stream again from there. No event is lost and none comes twice.
 */
final class ChangeStreams {

    private static final int CURSOR_NOT_FOUND = 43;
    private static final String RESUMABLE = "ResumableChangeStreamError";
    private static final DecoderContext DECODING = DecoderContext.builder().build();

    private ChangeStreams() {
    }

    /** Where a stream watches: a collection's name, 1 for a database, or the cluster. */
    record Target(String database, BsonValue aggregate, boolean wholeCluster) {

        static Target collection(String database, String collection) {
            return new Target(database, new BsonString(collection), false);
        }

        static Target database(String database) {
            return new Target(database, new BsonInt32(1), false);
        }

        static Target cluster() {
            return new Target("admin", new BsonInt32(1), true);
        }
    }

    static final class Stream<T> implements ChangeStreamIterable<T> {
        final Topology topology;
        final LogicalSession session;
        final ReadPreference preference;
        final CodecRegistry registry;
        final Class<T> documentClass;
        final Target target;
        final List<? extends Bson> pipeline;
        final Supplier<BsonDocument> readConcern;
        final Long timeoutMillis;
        FullDocument fullDocument;
        FullDocumentBeforeChange fullDocumentBeforeChange;
        BsonDocument resumeAfter;
        BsonDocument startAfter;
        BsonTimestamp startAtOperationTime;
        int batchSize;
        long maxAwaitMillis;
        Collation collation;
        BsonValue comment;
        boolean showExpandedEvents;

        Stream(Topology topology, LogicalSession session, ReadPreference preference,
                CodecRegistry registry, Class<T> documentClass, Target target,
                List<? extends Bson> pipeline, Supplier<BsonDocument> readConcern,
                Long timeoutMillis) {
            this.topology = topology;
            this.session = session;
            this.preference = preference;
            this.registry = registry;
            this.documentClass = documentClass;
            this.target = target;
            this.pipeline = pipeline;
            this.readConcern = readConcern;
            this.timeoutMillis = timeoutMillis;
        }

        /** The aggregation, starting where {@code from} says. */
        BsonDocument command(Start from) {
            BsonDocument stage = new BsonDocument();
            if (fullDocument != null && fullDocument != FullDocument.DEFAULT) {
                stage.put("fullDocument", new BsonString(fullDocument.getValue()));
            }
            if (fullDocumentBeforeChange != null
                    && fullDocumentBeforeChange != FullDocumentBeforeChange.DEFAULT) {
                stage.put("fullDocumentBeforeChange",
                        new BsonString(fullDocumentBeforeChange.getValue()));
            }
            from.apply(stage);
            if (target.wholeCluster()) {
                stage.put("allChangesForCluster", BsonBoolean.TRUE);
            }
            Bsons.putTrue(stage, "showExpandedEvents", showExpandedEvents);
            BsonArray stages = new BsonArray();
            stages.add(new BsonDocument("$changeStream", stage));
            stages.addAll(Bsons.toArray(pipeline, documentClass, registry));
            BsonDocument cursor = new BsonDocument();
            if (batchSize > 0) {
                cursor.put("batchSize", new BsonInt32(batchSize));
            }
            BsonDocument command = new BsonDocument("aggregate", target.aggregate())
                    .append("pipeline", stages).append("cursor", cursor);
            Bsons.put(command, "collation", collation);
            Bsons.put(command, "comment", comment);
            BsonDocument concern = readConcern.get();
            if (concern != null) {
                command.put("readConcern", concern);
            }
            return command;
        }

        /** The start the options give. */
        Start initialStart() {
            if (startAfter != null) {
                return new Start(startAfter, true, null);
            }
            if (resumeAfter != null) {
                return new Start(resumeAfter, false, null);
            }
            return new Start(null, false, startAtOperationTime);
        }

        Decoder<ChangeStreamDocument<T>> eventDecoder() {
            return ChangeStreamDocument.createCodec(documentClass, registry);
        }

        @Override
        public MongoChangeStreamCursor<ChangeStreamDocument<T>> cursor() {
            return new Cursor<>(this, eventDecoder());
        }

        @Override
        public MongoChangeStreamCursor<ChangeStreamDocument<T>> iterator() {
            return cursor();
        }

        /** The first event already there, or null - without waiting for one. */
        @Override
        public ChangeStreamDocument<T> first() {
            try (Cursor<ChangeStreamDocument<T>> cursor = new Cursor<>(this, eventDecoder())) {
                return cursor.firstBatchOnly();
            }
        }

        @Override
        public <U> MongoIterable<U> map(Function<ChangeStreamDocument<T>, U> mapper) {
            return new Iterables.Mapped<>(this, mapper);
        }

        /** Waits for events for as long as the stream lasts, as the official driver does. */
        @Override
        public <A extends Collection<? super ChangeStreamDocument<T>>> A into(A target) {
            try (MongoCursor<ChangeStreamDocument<T>> cursor = cursor()) {
                while (cursor.hasNext()) {
                    target.add(cursor.next());
                }
            }
            return target;
        }

        @Override
        public <D> MongoIterable<D> withDocumentClass(Class<D> type) {
            Stream<T> outer = this;
            Decoder<D> decoder = registry.get(type);
            return new Iterables.Mapped<>(new Raw(outer), raw -> decoder.decode(
                    new BsonDocumentReader(raw), DECODING));
        }

        @Override
        public ChangeStreamIterable<T> fullDocument(FullDocument fullDocument) {
            this.fullDocument = fullDocument;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> fullDocumentBeforeChange(FullDocumentBeforeChange before) {
            this.fullDocumentBeforeChange = before;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> resumeAfter(BsonDocument resumeToken) {
            this.resumeAfter = resumeToken;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> maxAwaitTime(long maxAwaitTime, TimeUnit unit) {
            this.maxAwaitMillis = Bsons.millis(maxAwaitTime, unit);
            return this;
        }

        @Override
        public ChangeStreamIterable<T> collation(Collation collation) {
            this.collation = collation;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> startAtOperationTime(BsonTimestamp startAtOperationTime) {
            this.startAtOperationTime = startAtOperationTime;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> startAfter(BsonDocument startAfter) {
            this.startAfter = startAfter;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> comment(String comment) {
            this.comment = comment == null ? null : new BsonString(comment);
            return this;
        }

        @Override
        public ChangeStreamIterable<T> comment(BsonValue comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public ChangeStreamIterable<T> showExpandedEvents(boolean showExpandedEvents) {
            this.showExpandedEvents = showExpandedEvents;
            return this;
        }
    }

    /** The raw events of a stream, for withDocumentClass. */
    private static final class Raw implements MongoIterable<BsonDocument> {
        private final Stream<?> stream;

        Raw(Stream<?> stream) {
            this.stream = stream;
        }

        @Override
        public MongoCursor<BsonDocument> iterator() {
            return new Cursor<>(stream, new BsonDocumentCodec());
        }

        @Override
        public MongoCursor<BsonDocument> cursor() {
            return iterator();
        }

        @Override
        public BsonDocument first() {
            try (Cursor<BsonDocument> cursor = new Cursor<>(stream, new BsonDocumentCodec())) {
                return cursor.firstBatchOnly();
            }
        }

        @Override
        public <U> MongoIterable<U> map(Function<BsonDocument, U> mapper) {
            return new Iterables.Mapped<>(this, mapper);
        }

        @Override
        public <A extends Collection<? super BsonDocument>> A into(A target) {
            try (MongoCursor<BsonDocument> cursor = iterator()) {
                while (cursor.hasNext()) {
                    target.add(cursor.next());
                }
            }
            return target;
        }

        @Override
        public MongoIterable<BsonDocument> batchSize(int batchSize) {
            stream.batchSize(batchSize);
            return this;
        }
    }

    /** Where a stream is opened from: a token (after it, or start after it) or a time. */
    record Start(BsonDocument token, boolean startAfter, BsonTimestamp operationTime) {

        void apply(BsonDocument stage) {
            if (token != null) {
                stage.put(startAfter ? "startAfter" : "resumeAfter", token);
            } else if (operationTime != null) {
                stage.put("startAtOperationTime", operationTime);
            }
        }
    }

    static final class Cursor<R> implements MongoChangeStreamCursor<R> {
        private final Stream<?> stream;
        private final Decoder<R> decoder;
        private BatchCursor<BsonDocument> cursor;
        private BsonDocument resumeToken;
        private BsonTimestamp operationTime;
        private boolean anyEvent;
        private BsonDocument buffered;

        Cursor(Stream<?> stream, Decoder<R> decoder) {
            this.stream = stream;
            this.decoder = decoder;
            Start start = stream.initialStart();
            this.resumeToken = start.token();
            open(start);
        }

        private void open(Start start) {
            try (Deadline.Scope _ = Deadline.perBatch(stream.timeoutMillis)) {
                Topology.Reply reply = stream.topology.read(stream.session, stream.preference,
                        stream.target.database(), stream.command(start));
                if (resumeToken == null && start.operationTime() == null
                        && reply.document().containsKey("operationTime")) {
                    // Nothing to resume from yet: the time the stream began is.
                    operationTime = reply.document().getTimestamp("operationTime");
                } else if (start.operationTime() != null) {
                    operationTime = start.operationTime();
                }
                cursor = new BatchCursor<>(stream.topology, reply, stream.session,
                        new BsonDocumentCodec(), stream.batchSize, stream.maxAwaitMillis,
                        stream.comment);
                if (cursor.batchDone() && cursor.postBatchResumeToken() != null) {
                    resumeToken = cursor.postBatchResumeToken();
                }
            }
        }

        /** Where to open the stream again: after the last event seen, else where it began. */
        private Start resumePoint() {
            if (resumeToken != null) {
                // startAfter works past an invalidate; once an event came, resumeAfter.
                boolean after = stream.startAfter != null && !anyEvent;
                return new Start(resumeToken, after, null);
            }
            return new Start(null, false, operationTime);
        }

        private static boolean resumable(MongoException e) {
            if (e instanceof MongoSocketException) {
                return true;
            }
            if (e instanceof MongoCommandException command) {
                return command.getErrorCode() == CURSOR_NOT_FOUND || e.hasErrorLabel(RESUMABLE);
            }
            return e.hasErrorLabel(RESUMABLE);
        }

        /** One event, or null after one getMore at most; resumes once on a resumable error. */
        private BsonDocument tryNextRaw() {
            for (int attempt = 0; ; attempt++) {
                try (Deadline.Scope _ = Deadline.perBatch(stream.timeoutMillis)) {
                    BsonDocument event = cursor.tryNext();
                    if (event == null) {
                        if (cursor.postBatchResumeToken() != null) {
                            resumeToken = cursor.postBatchResumeToken();
                        }
                        return null;
                    }
                    BsonValue id = event.get("_id");
                    if (!(id instanceof BsonDocument token)) {
                        cursor.close();
                        throw new MongoChangeStreamException("an event without its resume token "
                                + "(_id) - a pipeline that removes _id leaves nothing to resume "
                                + "from");
                    }
                    resumeToken = cursor.batchDone() && cursor.postBatchResumeToken() != null
                            ? cursor.postBatchResumeToken() : token;
                    anyEvent = true;
                    return event;
                } catch (MongoException e) {
                    if (!resumable(e) || attempt > 0) {
                        throw e;
                    }
                    cursor.close();
                    open(resumePoint());
                }
            }
        }

        /** The first batch as it came - first() waits for nothing. */
        R firstBatchOnly() {
            if (cursor.batchDone()) {
                return null;
            }
            BsonDocument event = cursor.tryNext();
            return event == null ? null : decoder.decode(new BsonDocumentReader(event), DECODING);
        }

        @Override
        public boolean hasNext() {
            while (buffered == null) {
                buffered = tryNextRaw();
            }
            return true;
        }

        @Override
        public R next() {
            if (!hasNext()) {
                throw new NoSuchElementException("next() on a change stream that has ended");
            }
            BsonDocument event = buffered;
            buffered = null;
            return decoder.decode(new BsonDocumentReader(event), DECODING);
        }

        @Override
        public R tryNext() {
            BsonDocument event = buffered != null ? buffered : tryNextRaw();
            buffered = null;
            return event == null ? null : decoder.decode(new BsonDocumentReader(event), DECODING);
        }

        @Override
        public int available() {
            return cursor.available() + (buffered == null ? 0 : 1);
        }

        @Override
        public BsonDocument getResumeToken() {
            return resumeToken;
        }

        @Override
        public ServerCursor getServerCursor() {
            return cursor.getServerCursor();
        }

        @Override
        public ServerAddress getServerAddress() {
            return cursor.getServerAddress();
        }

        @Override
        public void close() {
            cursor.close();
        }
    }
}
