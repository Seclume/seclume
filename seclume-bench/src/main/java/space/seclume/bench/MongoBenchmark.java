package space.seclume.bench;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.model.Filters;

import space.seclume.mongodb.SeclumeMongo;
import space.seclume.mongodb.driver.SeclumeMongoClients;

/**
 * MongoDB - seclume's own driver against the official one, and the official
 * one on seclume's pre-authenticated socket.
 *
 * <ul>
 *   <li>{@code official}: {@code mongodb-driver-sync} as it comes, SCRAM-SHA-256
 *       with the password in a {@code MongoCredential} - the baseline;</li>
 *   <li>{@code seclume}: {@code SeclumeMongoClients}, the same
 *       {@code com.mongodb.client} API over seclume's driver and TLS;</li>
 *   <li>{@code socket}: the official driver whose connections seclume opened
 *       and logged in ({@code SeclumeMongo.client}).</li>
 * </ul>
 *
 * <p>Each client keeps its own pool and is asked as an application asks it:
 * a command, a document by {@code _id}, a thousand documents through the
 * cursor in its default batches, one insert, a batch of 500. The login is
 * not measured: the clients are opened once per trial.
 *
 * <pre>
 *   -Dbench.mongo.host=127.0.0.1 -Dbench.mongo.port=27017
 *   -Dbench.mongo.user=seclume_test -Dbench.mongo.authSource=admin
 *   -Dbench.mongo.password.file=... -Dbench.mongo.ca=...
 * </pre>
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Measurement(iterations = 5, time = 3)
@State(Scope.Benchmark)
public class MongoBenchmark {

    /** Which client this run measures. */
    @Param({"seclume", "official", "socket"})
    public String driver;

    /** How many documents the large read returns. */
    @Param({"1000"})
    public int documents;

    private MongoClient client;
    private MongoCollection<Document> read;
    private MongoCollection<Document> write;
    private Document ping;
    private int next;

    @Setup(Level.Trial)
    public void open() throws Exception {
        String host = System.getProperty("bench.mongo.host", "127.0.0.1");
        int port = Integer.getInteger("bench.mongo.port", 27017);
        String user = System.getProperty("bench.mongo.user", "seclume_test");
        String authSource = System.getProperty("bench.mongo.authSource", "admin");
        Path password = Path.of(required("bench.mongo.password.file"));
        Path ca = Path.of(required("bench.mongo.ca"));
        String url = "mongodb://" + user + "@" + host + ":" + port + "/?authSource=" + authSource
                + "&provider=file&path=" + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/');
        client = switch (driver) {
            case "seclume" -> SeclumeMongoClients.create(url);
            case "socket" -> SeclumeMongo.client(url);
            case "official" -> MongoClients.create(MongoClientSettings.builder()
                    .applyConnectionString(new ConnectionString(
                            "mongodb://" + host + ":" + port + "/?tls=true"))
                    .applyToSslSettings(ssl -> ssl.context(trusting(ca)))
                    .credential(MongoCredential.createScramSha256Credential(user, authSource,
                            // seclume-allow: the official driver takes the password itself - that is the very thing being compared here, and this is the measuring harness, not the library
                            Files.readString(password, StandardCharsets.UTF_8).strip()
                                    .toCharArray()))
                    .build());
            default -> throw new IllegalArgumentException("unknown driver '" + driver
                    + "' - seclume, official or socket");
        };
        read = client.getDatabase("seclume_test").getCollection("bench_read_" + driver);
        write = client.getDatabase("seclume_test").getCollection("bench_write_" + driver);
        read.drop();
        List<Document> rows = new ArrayList<>(documents);
        for (int i = 0; i < documents; i++) {
            rows.add(new Document("_id", i).append("name", "row " + i).append("value", i * 1.5));
        }
        read.insertMany(rows);
        ping = new Document("ping", 1);
    }

    @Setup(Level.Iteration)
    public void emptyTheWrites() {
        write.drop();
    }

    @TearDown(Level.Trial)
    public void close() {
        if (client != null) {
            read.drop();
            write.drop();
            client.close();
        }
    }

    private static String required(String property) {
        String value = System.getProperty(property);
        if (value == null) {
            throw new IllegalStateException("-D" + property + " is required");
        }
        return value;
    }

    /** The official driver's TLS: the fixture's CA, the JDK's own trust machinery. */
    private static SSLContext trusting(Path ca) {
        try (InputStream in = Files.newInputStream(ca)) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            int n = 0;
            for (Certificate certificate : CertificateFactory.getInstance("X.509")
                    .generateCertificates(in)) {
                store.setCertificateEntry("ca" + n++, certificate);
            }
            TrustManagerFactory trust = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            SSLContext context = SSLContext.getInstance("TLSv1.3"); // as seclume speaks it
            context.init(null, trust.getTrustManagers(), null);
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("the CA file could not be read: " + ca, e);
        }
    }

    @Benchmark
    public void ping(Blackhole hole) {
        hole.consume(client.getDatabase("admin").runCommand(ping));
    }

    @Benchmark
    public void findOne(Blackhole hole) {
        Document found = read.find(Filters.eq("_id", 7)).first();
        hole.consume(found.getString("name"));
        hole.consume(found.getDouble("value"));
    }

    @Benchmark
    public void findMany(Blackhole hole) {
        try (MongoCursor<Document> cursor = read.find().iterator()) {
            while (cursor.hasNext()) {
                Document row = cursor.next();
                hole.consume(row.getInteger("_id"));
                hole.consume(row.getString("name"));
                hole.consume(row.getDouble("value"));
            }
        }
    }

    @Benchmark
    public void insertOne(Blackhole hole) {
        hole.consume(write.insertOne(new Document("_id", new ObjectId())
                .append("name", "row").append("value", next++ * 1.5)));
    }

    @Benchmark
    public void insertMany(Blackhole hole) {
        List<Document> batch = new ArrayList<>(500);
        for (int i = 0; i < 500; i++) {
            batch.add(new Document("_id", new ObjectId()).append("name", "row " + i)
                    .append("value", i * 1.5));
        }
        hole.consume(write.insertMany(batch));
    }
}
