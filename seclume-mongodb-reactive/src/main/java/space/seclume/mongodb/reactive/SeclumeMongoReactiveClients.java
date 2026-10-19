package space.seclume.mongodb.reactive;

import org.bson.codecs.configuration.CodecRegistry;

import com.mongodb.MongoClientSettings;
import com.mongodb.reactivestreams.client.MongoClient;

import space.seclume.mongodb.driver.SeclumeMongoClients;

/**
 * seclume's MongoDB driver behind the reactive API of the official driver
 * ({@code com.mongodb.reactivestreams.client}), in place of
 * {@code MongoClients} there - for Spring WebFlux and Spring Data's reactive
 * repositories, and anything else written against Reactive Streams.
 *
 * <p>Under it is the sync driver, unchanged: the same login off the heap, the
 * same pool, sessions and transactions. Each subscription runs on a virtual
 * thread of its own (see Publishers), so a blocking call blocks nobody but
 * that thread.
 */
public final class SeclumeMongoReactiveClients {

    private SeclumeMongoReactiveClients() {
    }

    public static MongoClient create(String url) {
        return create(url, MongoClientSettings.getDefaultCodecRegistry());
    }

    public static MongoClient create(String url, CodecRegistry codecs) {
        return new ReactiveClient(SeclumeMongoClients.create(url, codecs));
    }
}
