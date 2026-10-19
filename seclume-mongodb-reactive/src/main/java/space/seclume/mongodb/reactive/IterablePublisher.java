package space.seclume.mongodb.reactive;

import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;

import com.mongodb.client.MongoIterable;

/**
 * What every publisher of documents shares: subscribing reads the sync
 * iterable's cursor as demand allows. The iterable is built when the
 * publisher is - lazily, as the sync driver builds it - and run anew for each
 * subscriber.
 */
abstract class IterablePublisher<T> implements Publisher<T> {

    private final MongoIterable<T> iterable;

    IterablePublisher(MongoIterable<T> iterable) {
        this.iterable = iterable;
    }

    @Override
    public void subscribe(Subscriber<? super T> subscriber) {
        Publishers.many(iterable::cursor).subscribe(subscriber);
    }
}
