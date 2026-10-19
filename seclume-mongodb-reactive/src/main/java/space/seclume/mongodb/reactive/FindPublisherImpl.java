package space.seclume.mongodb.reactive;

/**
 * Generated from the reactive and the sync API: every method of
 * {@code com.mongodb.reactivestreams.client.FindPublisher} on {@code com.mongodb.client.FindIterable} (see Publishers for how a call becomes a
 * publisher). Regenerate rather than edit.
 */
@SuppressWarnings({"deprecation", "unchecked", "rawtypes"})
final class FindPublisherImpl<TResult> extends IterablePublisher<TResult> implements com.mongodb.reactivestreams.client.FindPublisher<TResult> {

    private final com.mongodb.client.FindIterable<TResult> sync;

    FindPublisherImpl(com.mongodb.client.FindIterable<TResult> sync) {
        super(sync);
        this.sync = sync;
    }

    @Override
    public org.reactivestreams.Publisher<TResult> first() {
        return Publishers.single(() -> sync.first());
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> filter(org.bson.conversions.Bson arg0) {
        sync.filter(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> limit(int arg0) {
        sync.limit(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> skip(int arg0) {
        sync.skip(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> maxTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> maxAwaitTime(long arg0, java.util.concurrent.TimeUnit arg1) {
        sync.maxAwaitTime(arg0, arg1);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> projection(org.bson.conversions.Bson arg0) {
        sync.projection(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> sort(org.bson.conversions.Bson arg0) {
        sync.sort(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> noCursorTimeout(boolean arg0) {
        sync.noCursorTimeout(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> partial(boolean arg0) {
        sync.partial(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> cursorType(com.mongodb.CursorType arg0) {
        sync.cursorType(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> collation(com.mongodb.client.model.Collation arg0) {
        sync.collation(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> comment(java.lang.String arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> comment(org.bson.BsonValue arg0) {
        sync.comment(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> hint(org.bson.conversions.Bson arg0) {
        sync.hint(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> hintString(java.lang.String arg0) {
        sync.hintString(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> let(org.bson.conversions.Bson arg0) {
        sync.let(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> max(org.bson.conversions.Bson arg0) {
        sync.max(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> min(org.bson.conversions.Bson arg0) {
        sync.min(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> returnKey(boolean arg0) {
        sync.returnKey(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> showRecordId(boolean arg0) {
        sync.showRecordId(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> batchSize(int arg0) {
        sync.batchSize(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> allowDiskUse(java.lang.Boolean arg0) {
        sync.allowDiskUse(arg0);
        return this;
    }

    @Override
    public com.mongodb.reactivestreams.client.FindPublisher<TResult> timeoutMode(com.mongodb.client.cursor.TimeoutMode arg0) {
        sync.timeoutMode(arg0);
        return this;
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> explain() {
        return Publishers.single(() -> sync.explain());
    }

    @Override
    public org.reactivestreams.Publisher<org.bson.Document> explain(com.mongodb.ExplainVerbosity arg0) {
        return Publishers.single(() -> sync.explain(arg0));
    }

    @Override
    public <E> org.reactivestreams.Publisher<E> explain(java.lang.Class<E> arg0) {
        return Publishers.single(() -> sync.explain(arg0));
    }

    @Override
    public <E> org.reactivestreams.Publisher<E> explain(java.lang.Class<E> arg0, com.mongodb.ExplainVerbosity arg1) {
        return Publishers.single(() -> sync.explain(arg0, arg1));
    }

}
