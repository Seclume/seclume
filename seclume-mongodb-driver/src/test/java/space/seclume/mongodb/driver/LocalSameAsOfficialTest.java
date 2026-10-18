package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoBulkWriteException;
import com.mongodb.MongoCommandException;
import com.mongodb.MongoWriteException;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Accumulators;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.BulkWriteOptions;
import com.mongodb.client.model.DeleteOneModel;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.InsertManyOptions;
import com.mongodb.client.model.InsertOneModel;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.ReplaceOptions;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.UpdateOneModel;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.model.Updates;

import space.seclume.mongodb.SeclumeMongo;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * The same operations through the official driver and through seclume's,
 * against the same server: every result, and every refusal, has to come out
 * the same. The official driver here runs over seclume-mongodb's
 * pre-authenticated socket, so both sides log in the same way.
 */
@Timeout(180)
class LocalSameAsOfficialTest {

    private static Path passwordFile;
    private static String url;
    private static MongoClient official;
    private static MongoClient seclume;

    @BeforeAll
    static void bothClients() {
        String host = System.getProperty("seclume.mongo.host", TestHosts.database());
        int port = Integer.getInteger("seclume.mongo.port", 27017);
        passwordFile = find(".local-mongo-password");
        Path ca = find(".local-mongo-ca.pem");
        assumeTrue(passwordFile != null && ca != null, "no MongoDB fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + host + ":" + port);
        }
        url = "mongodb://seclume_test@" + host + ":" + port + "/?authSource=admin&provider=file"
                + "&path=" + passwordFile.toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/');
        official = SeclumeMongo.client(url);
        seclume = SeclumeMongoClients.create(url);
    }

    @AfterAll
    static void close() {
        if (official != null) {
            official.close();
        }
        if (seclume != null) {
            seclume.close();
        }
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    /** Runs a scenario on a fresh collection per client and compares what each saw. */
    private static void same(Function<MongoCollection<Document>, List<Object>> scenario) {
        String name = "zl_same_" + new ObjectId().toHexString();
        MongoDatabase officialDb = official.getDatabase("seclume_test");
        MongoDatabase seclumeDb = seclume.getDatabase("seclume_test");
        MongoCollection<Document> a = officialDb.getCollection(name + "_o");
        MongoCollection<Document> b = seclumeDb.getCollection(name + "_s");
        try {
            List<Object> expected = scenario.apply(a);
            List<Object> actual = scenario.apply(b);
            assertEquals(expected, actual);
        } finally {
            a.drop();
            b.drop();
        }
    }

    private static List<Document> people() {
        List<Document> people = new ArrayList<>();
        String[] names = {"ada", "bob", "cy", "dee", "eve", "fay", "gus"};
        for (int i = 0; i < names.length; i++) {
            people.add(new Document("_id", i).append("name", names[i]).append("age", 20 + i * 3)
                    .append("team", i % 3).append("tags", List.of("t" + (i % 2), "all")));
        }
        return people;
    }

    @Test
    void insertFindSortProjectSkipLimit() {
        same(c -> {
            List<Object> seen = new ArrayList<>();
            seen.add(c.insertMany(people()).getInsertedIds().size());
            seen.add(c.find(Filters.gte("age", 26)).sort(Sorts.descending("age"))
                    .projection(Projections.include("name")).skip(1).limit(2)
                    .into(new ArrayList<>()));
            seen.add(c.find(Filters.eq("tags", "t1")).sort(Sorts.ascending("_id"))
                    .batchSize(2).into(new ArrayList<>()));
            seen.add(c.find(Filters.eq("name", "nobody")).first());
            seen.add(c.find().sort(Sorts.ascending("age")).first());
            seen.add(c.countDocuments());
            seen.add(c.countDocuments(Filters.lt("age", 30)));
            seen.add(c.estimatedDocumentCount());
            seen.add(c.distinct("team", Integer.class).into(new ArrayList<>()));
            return seen;
        });
    }

    @Test
    void manySmallBatchesThroughGetMore() {
        same(c -> {
            List<Document> many = new ArrayList<>();
            for (int i = 0; i < 1234; i++) {
                many.add(new Document("_id", i).append("v", "x".repeat(i % 50)));
            }
            c.insertMany(many);
            List<Object> seen = new ArrayList<>();
            List<Integer> ids = new ArrayList<>();
            c.find().sort(Sorts.ascending("_id")).batchSize(100)
                    .map(d -> d.getInteger("_id")).into(ids);
            seen.add(ids.size());
            seen.add(ids.get(1233));
            try (var cursor = c.find().batchSize(10).cursor()) {
                seen.add(cursor.hasNext());
                cursor.next();
                seen.add(cursor.available());
            }
            return seen;
        });
    }

    @Test
    void updatesReplacesAndDeletes() {
        same(c -> {
            c.insertMany(people());
            List<Object> seen = new ArrayList<>();
            var one = c.updateOne(Filters.eq("name", "bob"), Updates.inc("age", 1));
            seen.add(List.of(one.getMatchedCount(), one.getModifiedCount(),
                    String.valueOf(one.getUpsertedId())));
            var many = c.updateMany(Filters.eq("team", 0), Updates.set("lead", true));
            seen.add(List.of(many.getMatchedCount(), many.getModifiedCount()));
            var upsert = c.updateOne(Filters.eq("_id", 99), Updates.set("name", "new"),
                    new UpdateOptions().upsert(true));
            seen.add(List.of(upsert.getMatchedCount(), upsert.getModifiedCount(),
                    String.valueOf(upsert.getUpsertedId())));
            var pipeline = c.updateMany(Filters.exists("age"),
                    List.of(Aggregates.set(new com.mongodb.client.model.Field<>("old",
                            new Document("$gt", List.of("$age", 30))))));
            seen.add(pipeline.getModifiedCount());
            var replaced = c.replaceOne(Filters.eq("_id", 1), new Document("name", "robert"));
            seen.add(List.of(replaced.getMatchedCount(), replaced.getModifiedCount()));
            var replaceUpsert = c.replaceOne(Filters.eq("_id", 100), new Document("n", 1),
                    new ReplaceOptions().upsert(true));
            seen.add(String.valueOf(replaceUpsert.getUpsertedId()));
            seen.add(c.deleteOne(Filters.eq("team", 1)).getDeletedCount());
            seen.add(c.deleteMany(Filters.eq("team", 2)).getDeletedCount());
            seen.add(c.find().sort(Sorts.ascending("_id")).into(new ArrayList<>()));
            return seen;
        });
    }

    @Test
    void findOneAndFriends() {
        same(c -> {
            c.insertMany(people());
            List<Object> seen = new ArrayList<>();
            seen.add(c.findOneAndUpdate(Filters.eq("name", "cy"), Updates.inc("age", 10)));
            seen.add(c.findOneAndUpdate(Filters.eq("name", "cy"), Updates.inc("age", 10),
                    new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER)
                            .projection(Projections.excludeId())));
            seen.add(c.findOneAndReplace(Filters.eq("_id", 4), new Document("name", "evie")));
            seen.add(c.findOneAndDelete(Filters.eq("team", 0)));
            seen.add(c.findOneAndDelete(Filters.eq("name", "nobody")));
            seen.add(c.countDocuments());
            return seen;
        });
    }

    @Test
    void aggregateIndexesAndBulk() {
        same(c -> {
            c.insertMany(people());
            List<Object> seen = new ArrayList<>();
            seen.add(c.aggregate(List.of(
                    Aggregates.group("$team", Accumulators.sum("n", 1),
                            Accumulators.avg("age", "$age")),
                    Aggregates.sort(Sorts.ascending("_id")))).into(new ArrayList<>()));
            seen.add(c.createIndex(Indexes.compoundIndex(Indexes.ascending("team"),
                    Indexes.descending("age"))));
            seen.add(c.createIndex(Indexes.ascending("name"), new IndexOptions().unique(true)));
            List<String> names = new ArrayList<>();
            c.listIndexes().map(i -> i.getString("name")).into(names);
            names.sort(null);
            seen.add(names);
            c.dropIndex("team_1_age_-1");
            var bulk = c.bulkWrite(List.of(
                    new InsertOneModel<>(new Document("_id", 50).append("name", "zed")),
                    new UpdateOneModel<>(Filters.eq("_id", 50), Updates.set("age", 1)),
                    new DeleteOneModel<>(Filters.eq("_id", 0)),
                    new InsertOneModel<>(new Document("_id", 51).append("name", "zoe"))));
            seen.add(List.of(bulk.getInsertedCount(), bulk.getMatchedCount(),
                    bulk.getModifiedCount(), bulk.getDeletedCount(), bulk.getInserts().size()));
            return seen;
        });
    }

    /** The refusals: the same exception types with the same codes and counts. */
    @Test
    void refusalsAreTheSame() {
        same(c -> {
            c.createIndex(Indexes.ascending("name"), new IndexOptions().unique(true));
            c.insertOne(new Document("_id", 1).append("name", "ada"));
            List<Object> seen = new ArrayList<>();
            try {
                c.insertOne(new Document("_id", 2).append("name", "ada"));
                seen.add("no error");
            } catch (MongoWriteException e) {
                seen.add(List.of("write", e.getCode(), e.getError().getCategory().name()));
            }
            try {
                c.insertMany(List.of(new Document("_id", 3).append("name", "bob"),
                        new Document("_id", 4).append("name", "ada"),
                        new Document("_id", 5).append("name", "cy")));
                seen.add("no error");
            } catch (MongoBulkWriteException e) {
                seen.add(List.of("bulk", e.getWriteErrors().size(),
                        e.getWriteErrors().get(0).getIndex(), e.getWriteErrors().get(0).getCode(),
                        e.getWriteResult().getInsertedCount()));
            }
            try {
                c.insertMany(List.of(new Document("_id", 6).append("name", "ada"),
                        new Document("_id", 7).append("name", "dee")),
                        new InsertManyOptions().ordered(false));
                seen.add("no error");
            } catch (MongoBulkWriteException e) {
                seen.add(List.of("unordered", e.getWriteErrors().size(),
                        e.getWriteResult().getInsertedCount()));
            }
            try {
                c.bulkWrite(List.of(new InsertOneModel<>(new Document("_id", 8)),
                        new InsertOneModel<>(new Document("_id", 1)),
                        new InsertOneModel<>(new Document("_id", 9))),
                        new BulkWriteOptions().ordered(true));
                seen.add("no error");
            } catch (MongoBulkWriteException e) {
                seen.add(List.of("bulkWrite", e.getWriteErrors().get(0).getIndex(),
                        e.getWriteResult().getInsertedCount()));
            }
            try {
                c.find(new Document("$bogus", 1)).first();
                seen.add("no error");
            } catch (MongoCommandException e) {
                seen.add(List.of("command", e.getErrorCode()));
            }
            try {
                c.updateOne(Filters.eq("_id", 1), new Document("plain", 1));
                seen.add("no error");
            } catch (IllegalArgumentException e) {
                seen.add("refused before sending");
            }
            seen.add(c.countDocuments());
            return seen;
        });
    }

    @Test
    void databaseLevel() throws Exception {
        MongoDatabase officialDb = official.getDatabase("seclume_test");
        MongoDatabase seclumeDb = seclume.getDatabase("seclume_test");
        String name = "zl_db_" + new ObjectId().toHexString();
        try {
            seclumeDb.createCollection(name);
            List<String> officialNames = officialDb.listCollectionNames().into(new ArrayList<>());
            List<String> seclumeNames = seclumeDb.listCollectionNames().into(new ArrayList<>());
            officialNames.sort(null);
            seclumeNames.sort(null);
            assertEquals(officialNames, seclumeNames);
            assertEquals(officialDb.runCommand(new Document("ping", 1)),
                    seclumeDb.runCommand(new Document("ping", 1)));
            assertEquals(official.listDatabaseNames().into(new ArrayList<>()).contains("admin"),
                    seclume.listDatabaseNames().into(new ArrayList<>()).contains("admin"));
            assertEquals(List.of(new Document("x", 1)), seclumeDb.aggregate(List.of(
                    new Document("$documents", List.of(new Document("x", 1)))))
                    .into(new ArrayList<>()));
        } finally {
            seclumeDb.getCollection(name).drop();
        }
        NoSecretInHeap.assertAbsent(passwordFile);
    }
}
