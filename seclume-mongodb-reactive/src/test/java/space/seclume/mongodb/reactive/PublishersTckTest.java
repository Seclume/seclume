package space.seclume.mongodb.reactive;

import java.util.NoSuchElementException;

import org.reactivestreams.Publisher;
import org.reactivestreams.tck.PublisherVerification;
import org.reactivestreams.tck.TestEnvironment;

import com.mongodb.ServerAddress;
import com.mongodb.ServerCursor;
import com.mongodb.client.MongoCursor;

/**
 * The Reactive Streams TCK on the cursor publisher every document publisher
 * here is: rules 1.x for publishers and 3.x for subscriptions, against a
 * cursor of any length and one that fails - each rule a test of its own.
 */
public class PublishersTckTest extends PublisherVerification<Long> {

    public PublishersTckTest() {
        super(new TestEnvironment(500, 100));
    }

    /** A cursor of {@code count} numbers, standing in for a server's cursor. */
    static MongoCursor<Long> numbers(long count) {
        return new MongoCursor<>() {
            private long next;

            @Override
            public boolean hasNext() {
                return next < count;
            }

            @Override
            public Long next() {
                if (next >= count) {
                    throw new NoSuchElementException("past the end of a test cursor");
                }
                return next++;
            }

            @Override
            public int available() {
                return 0;
            }

            @Override
            public Long tryNext() {
                return hasNext() ? next() : null;
            }

            @Override
            public ServerCursor getServerCursor() {
                return null;
            }

            @Override
            public ServerAddress getServerAddress() {
                return null;
            }

            @Override
            public void close() {
            }
        };
    }

    @Override
    public Publisher<Long> createPublisher(long elements) {
        return Publishers.many(() -> numbers(elements));
    }

    @Override
    public Publisher<Long> createFailedPublisher() {
        return Publishers.many(() -> {
            throw new IllegalStateException("the cursor could not be opened");
        });
    }

    /** Cursors are long by nature; the TCK's longest is enough. */
    @Override
    public long maxElementsFromPublisher() {
        return Long.MAX_VALUE - 1;
    }
}
