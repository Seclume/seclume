package space.seclume.mongodb.driver;

import org.bson.codecs.configuration.CodecRegistry;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.ReadConcern;
import com.mongodb.ReadPreference;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoClient;

import space.seclume.mongodb.MongoUrl;
import space.seclume.mongodb.driver.internal.Topology;

/**
 * seclume's own MongoDB driver, in place of {@code MongoClients}: the client
 * it returns implements the official sync API, so the code that uses it
 * stays as it is.
 *
 * <pre>{@code
 * MongoClient client = SeclumeMongoClients.create(
 *         "mongodb://app@db.example.com/?authSource=admin&provider=file&path=/run/secrets/mongo");
 * }</pre>
 *
 * <p>The URL is seclume's MongoDB URL: no password in it, the password from
 * a secret provider, TLS 1.3 always, SCRAM-SHA-256 only. The official URL
 * options this driver understands so far: {@code maxPoolSize},
 * {@code waitQueueTimeoutMS}, {@code readPreference}, {@code w},
 * {@code journal}, {@code wtimeoutMS} and {@code readConcernLevel}.
 */
public final class SeclumeMongoClients {

    private SeclumeMongoClients() {
    }

    /** A client with the default codecs ({@link MongoClientSettings#getDefaultCodecRegistry}). */
    public static MongoClient create(String url) {
        return create(url, MongoClientSettings.getDefaultCodecRegistry());
    }

    /** A client with the application's codecs - POJOs, records, its own types. */
    public static MongoClient create(String url, CodecRegistry codecs) {
        MongoUrl parsed = MongoUrl.parse(url);
        Topology topology = Topology.of(parsed);
        ConnectionString options = topology.options();
        ReadPreference preference = options.getReadPreference() != null
                ? options.getReadPreference() : ReadPreference.primary();
        WriteConcern concern = options.getWriteConcern() != null
                ? options.getWriteConcern() : WriteConcern.ACKNOWLEDGED;
        ReadConcern readConcern = options.getReadConcern() != null
                ? options.getReadConcern() : ReadConcern.DEFAULT;
        return new SeclumeClient(topology, codecs, preference, concern, readConcern);
    }
}
