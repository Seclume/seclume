package space.seclume.mongospring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.bson.Document;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.aggregation.Aggregation;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** MongoTemplate on seclume's driver: queries, updates, upserts, findAndModify, bulk, aggregation. */
@SpringBootTest(classes = MongoApplication.class)
class SpringDataMongoTemplateOnMongoTest {

    private static final String URL = Fixture.standalone();

    @Autowired
    MongoTemplate template;

    @BeforeAll
    static void needsTheServer() {
        Fixture.assumeThere(URL, "standalone fixture");
    }

    @DynamicPropertySource
    static void url(DynamicPropertyRegistry properties) {
        properties.add("seclume.mongo.url", () -> URL);
        properties.add("spring.mongodb.database", () -> "seclume_test");
        properties.add("spring.data.mongodb.database", () -> "seclume_test");
        properties.add("spring.data.mongodb.auto-index-creation", () -> "true");
    }

    @BeforeEach
    void some() {
        template.remove(new Query(), Person.class);
        template.insertAll(List.of(
                new Person("ada@x", "Ada", 36, "London", List.of("math")),
                new Person("bob@x", "Bob", 25, "Paris", List.of("code")),
                new Person("cy@x", "Cy", 41, "London", List.of("art"))));
    }

    private static Query email(String email) {
        return Query.query(Criteria.where("email").is(email));
    }

    @Test
    void queries() {
        List<Person> london = template.find(Query.query(Criteria.where("address.city").is("London"))
                .with(Sort.by("age")), Person.class);
        assertEquals(List.of("Ada", "Cy"), london.stream().map(Person::getName).toList());
        assertEquals(2, template.count(Query.query(Criteria.where("age").gt(30)), Person.class));
        assertTrue(template.exists(email("bob@x"), Person.class));
        assertFalse(template.exists(email("nobody"), Person.class));
        assertEquals("Bob", template.findOne(email("bob@x"), Person.class).getName());
        assertEquals(List.of("London", "Paris"), template.findDistinct(new Query(),
                "address.city", Person.class, String.class).stream().sorted().toList());
    }

    @Test
    void updatesAndUpserts() {
        var result = template.updateMulti(Query.query(Criteria.where("age").gt(30)),
                new Update().inc("age", 1), Person.class);
        assertEquals(2, result.getModifiedCount());
        assertEquals(37, template.findOne(email("ada@x"), Person.class).getAge());
        var upsert = template.upsert(email("new@x"), new Update().set("name", "New")
                .set("age", 1), Person.class);
        assertTrue(upsert.getUpsertedId() != null);
        assertEquals(4, template.count(new Query(), Person.class));
    }

    @Test
    void findAndModifyAndRemove() {
        Person before = template.findAndModify(email("cy@x"), new Update().inc("age", 10),
                Person.class);
        assertEquals(41, before.getAge());
        Person after = template.findAndModify(email("cy@x"), new Update().inc("age", 10),
                FindAndModifyOptions.options().returnNew(true), Person.class);
        assertEquals(61, after.getAge());
        Person removed = template.findAndRemove(email("bob@x"), Person.class);
        assertEquals("Bob", removed.getName());
        assertNull(template.findOne(email("bob@x"), Person.class));
    }

    @Test
    void bulkOperations() {
        var bulk = template.bulkOps(BulkOperations.BulkMode.ORDERED, Person.class)
                .insert(new Person("dee@x", "Dee", 19, "Rome", List.of()))
                .updateOne(email("ada@x"), new Update().set("name", "Ada L."))
                .remove(email("bob@x"))
                .execute();
        assertEquals(1, bulk.getInsertedCount());
        assertEquals(1, bulk.getModifiedCount());
        assertEquals(1, bulk.getDeletedCount());
    }

    @Test
    void aggregation() {
        var aggregation = Aggregation.newAggregation(
                Aggregation.group("address.city").avg("age").as("averageAge"),
                Aggregation.sort(Sort.by("_id")));
        List<Document> perCity = template.aggregate(aggregation, Person.class, Document.class)
                .getMappedResults();
        assertEquals(2, perCity.size());
        assertEquals("London", perCity.get(0).getString("_id"));
        assertEquals(38.5, perCity.get(0).getDouble("averageAge"));
    }

    /** The index Spring Data made from @Indexed(unique = true) is there. */
    @Test
    void theIndexWasCreated() {
        List<String> names = template.indexOps(Person.class).getIndexInfo().stream()
                .map(index -> index.getName()).toList();
        assertTrue(names.contains("email"), names.toString());
    }
}
