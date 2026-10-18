package space.seclume.mongodb;

import java.lang.reflect.Field;

import javax.net.ssl.SSLContext;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;

/**
 * MongoDB through the official Java driver ({@code mongodb-driver-sync}) with
 * the password off the heap:
 *
 * <pre>
 * MongoClient mongo = SeclumeMongo.client(
 *         "mongodb://orders@cluster.example.invalid:27017/?authSource=admin&amp;provider=file&amp;path=/run/secrets/mongo");
 * MongoDatabase db = mongo.getDatabase("orders");
 * </pre>
 *
 * <p>The official driver given a password keeps it as a {@code char[]} in its
 * credentials and computes SCRAM on the heap at every connect; with TLS, JSSE
 * copies the plaintext again. Here the driver is given no credential at all:
 * seclume opens the connection, encrypts with its own TLS 1.3 stack, and runs
 * SCRAM-SHA-256 entirely in native memory before handing the authenticated
 * socket to the driver. The driver never holds the password.
 */
public final class SeclumeMongo {

    private SeclumeMongo() {
    }

    /**
     * Produces an {@link SSLContext} configured for pre-authenticated TLS
     * connections for the given MongoDB URL.
     */
    public static SSLContext sslContext(String url) {
        MongoUrl parsed = MongoUrl.parse(url);
        return new SeclumeMongoSslContext(parsed);
    }

    /**
     * Configures the given {@link MongoClientSettings.Builder} to use seclume's
     * pre-authenticated TLS context, with credentials left empty.
     */
    public static MongoClientSettings.Builder configure(MongoClientSettings.Builder builder,
                                                        String url) {
        MongoUrl parsed = MongoUrl.parse(url);
        SSLContext context = new SeclumeMongoSslContext(parsed);
        builder.applyConnectionString(new ConnectionString(parsed.driverConnectionString()))
                .applyToSslSettings(b -> b.enabled(true).context(context));
        clearCredential(builder);
        return builder;
    }

    /**
     * Builds ready-to-use {@link MongoClientSettings} for the given URL.
     */
    public static MongoClientSettings settings(String url) {
        return configure(MongoClientSettings.builder(), url).build();
    }

    /**
     * Creates a {@link MongoClient} connected through seclume's off-heap TLS
     * and SCRAM authentication.
     */
    public static MongoClient client(String url) {
        return MongoClients.create(settings(url));
    }

    private static void clearCredential(MongoClientSettings.Builder builder) {
        try {
            Field field = MongoClientSettings.Builder.class.getDeclaredField("credential");
            field.setAccessible(true);
            field.set(builder, null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to clear MongoCredential on builder", e);
        }
    }
}
