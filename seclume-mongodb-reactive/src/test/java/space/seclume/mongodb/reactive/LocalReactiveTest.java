package space.seclume.mongodb.reactive;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Sorts;
import com.mongodb.reactivestreams.client.ClientSession;
import com.mongodb.reactivestreams.client.MongoClient;
import com.mongodb.reactivestreams.client.MongoCollection;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/** The reactive API against the fixtures: CRUD, backpressure, a transaction, a change stream. */
@Timeout(120)
class LocalReactiveTest {

    private static final String HOST = System.getProperty("seclume.mongo.host",
            TestHosts.database());

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static String url(String hosts, String ca, String more) {
        Path password = find(".local-mongo-password");
        Path caFile = find(ca);
        assumeTrue(password != null && caFile != null, "no MongoDB fixture files");
        for (String host : hosts.split(",")) {
            String[] part = host.split(":");
            int port;
            try {
                port = Integer.parseInt(part[1]);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("not host:port: " + host, e);
            }
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(part[0], port), 2000);
            } catch (IOException e) {
                assumeTrue(false, "no MongoDB on " + host);
            }
        }
        return "mongodb://seclume_test@" + hosts + "/?authSource=admin&provider=file&path="
                + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + caFile.toString().replace('\\', '/') + more;
    }

    private static String standalone() {
        return url(HOST + ":27017", ".local-mongo-ca.pem", "");
    }

    private static String replicaSet() {
        return url(HOST + ":27021," + HOST + ":27022," + HOST + ":27023",
                ".local-mongo-rs-ca.pem", "&replicaSet=slm-rs");
    }

    /** Everything a publisher gives, asked for all at once. */
    static <T> List<T> all(Publisher<T> publisher) throws Exception {
        List<T> items = new CopyOnWriteArrayList<>();
        CompletableFuture<List<T>> done = new CompletableFuture<>();
        publisher.subscribe(new Subscriber<T>() {
            @Override
            public void onSubscribe(Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(T item) {
                items.add(item);
            }

            @Override
            public void onError(Throwable error) {
                done.completeExceptionally(error);
            }

            @Override
            public void onComplete() {
                done.complete(items);
            }
        });
        return done.get(30, TimeUnit.SECONDS);
    }

    private static MongoCollection<Document> fresh(MongoClient client) {
        return client.getDatabase("seclume_test").getCollection("zl_reactive_"
                + new ObjectId().toHexString());
    }

    @Test
    void crudThroughPublishers() throws Exception {
        try (MongoClient client = SeclumeMongoReactiveClients.create(standalone())) {
            MongoCollection<Document> things = fresh(client);
            try {
                List<Document> many = new ArrayList<>();
                for (int i = 0; i < 25; i++) {
                    many.add(new Document("_id", i).append("even", i % 2 == 0));
                }
                assertEquals(25, all(things.insertMany(many)).get(0).getInsertedIds().size());
                assertEquals(13L, all(things.countDocuments(Filters.eq("even", true))).get(0));
                List<Document> sorted = all(things.find(Filters.lt("_id", 5))
                        .sort(Sorts.descending("_id")).batchSize(2));
                assertEquals(List.of(4, 3, 2, 1, 0), sorted.stream()
                        .map(d -> d.getInteger("_id")).toList());
                assertEquals(1, all(things.find().first()).size());
                assertEquals(12L, all(things.deleteMany(Filters.eq("even", false))).get(0)
                        .getDeletedCount());
                assertEquals(List.of(true), all(things.distinct("even", Boolean.class)));
            } finally {
                all(things.drop());
            }
        }
        NoSecretInHeap.assertAbsent(find(".local-mongo-password"));
    }

    /** Asked for three at a time: three come, then nothing until more is asked for. */
    @Test
    void demandIsRespectedAndCancelStops() throws Exception {
        try (MongoClient client = SeclumeMongoReactiveClients.create(standalone())) {
            MongoCollection<Document> things = fresh(client);
            try {
                List<Document> many = new ArrayList<>();
                for (int i = 0; i < 100; i++) {
                    many.add(new Document("_id", i));
                }
                all(things.insertMany(many));
                List<Integer> seen = new CopyOnWriteArrayList<>();
                AtomicReference<Subscription> held = new AtomicReference<>();
                CompletableFuture<Boolean> ended = new CompletableFuture<>();
                things.find().sort(Sorts.ascending("_id")).batchSize(10).subscribe(
                        new Subscriber<Document>() {
                            @Override
                            public void onSubscribe(Subscription subscription) {
                                held.set(subscription);
                                subscription.request(3);
                            }

                            @Override
                            public void onNext(Document item) {
                                seen.add(item.getInteger("_id"));
                            }

                            @Override
                            public void onError(Throwable error) {
                                ended.completeExceptionally(error);
                            }

                            @Override
                            public void onComplete() {
                                ended.complete(true);
                            }
                        });
                long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (seen.size() < 3 && System.nanoTime() < until) {
                    Thread.sleep(10);
                }
                Thread.sleep(300);
                assertEquals(List.of(0, 1, 2), seen, "more came than was asked for");
                held.get().request(2);
                until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (seen.size() < 5 && System.nanoTime() < until) {
                    Thread.sleep(10);
                }
                assertEquals(List.of(0, 1, 2, 3, 4), seen);
                held.get().cancel();
                Thread.sleep(300);
                assertFalse(ended.isDone(), "a cancelled subscription was told it ended");
                assertEquals(5, seen.size());
            } finally {
                all(things.drop());
            }
        }
    }

    @Test
    void aTransactionThroughAReactiveSession() throws Exception {
        try (MongoClient client = SeclumeMongoReactiveClients.create(replicaSet())) {
            MongoCollection<Document> things = fresh(client);
            try {
                all(things.insertOne(new Document("_id", "seed")));
                ClientSession session = all(client.startSession()).get(0);
                try {
                    session.startTransaction();
                    all(things.insertOne(session, new Document("_id", "a")));
                    assertEquals(1L, all(things.countDocuments()).get(0),
                            "visible outside before the commit");
                    all(session.commitTransaction());
                    assertEquals(2L, all(things.countDocuments()).get(0));
                    session.startTransaction();
                    all(things.insertOne(session, new Document("_id", "b")));
                    all(session.abortTransaction());
                    assertEquals(2L, all(things.countDocuments()).get(0));
                } finally {
                    session.close();
                }
            } finally {
                all(things.drop());
            }
        }
    }

    @Test
    void aChangeStreamPublishes() throws Exception {
        try (MongoClient client = SeclumeMongoReactiveClients.create(replicaSet())) {
            MongoCollection<Document> things = fresh(client);
            try {
                all(things.insertOne(new Document("_id", "seed")));
                List<Object> keys = new CopyOnWriteArrayList<>();
                AtomicReference<Subscription> held = new AtomicReference<>();
                things.watch().maxAwaitTime(200, TimeUnit.MILLISECONDS).subscribe(
                        new Subscriber<>() {
                            @Override
                            public void onSubscribe(Subscription subscription) {
                                held.set(subscription);
                                subscription.request(Long.MAX_VALUE);
                            }

                            @Override
                            public void onNext(
                                    com.mongodb.client.model.changestream.ChangeStreamDocument<
                                            Document> event) {
                                keys.add(event.getDocumentKey().get("_id"));
                            }

                            @Override
                            public void onError(Throwable error) {
                            }

                            @Override
                            public void onComplete() {
                            }
                        });
                Thread.sleep(1000);                      // the stream is open
                all(things.insertOne(new Document("_id", "x")));
                long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (keys.isEmpty() && System.nanoTime() < until) {
                    Thread.sleep(20);
                }
                held.get().cancel();
                assertTrue(keys.size() == 1 && keys.get(0).toString().contains("x"),
                        keys.toString());
            } finally {
                all(things.drop());
            }
        }
    }
}
