package space.seclume.mongospring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import space.seclume.tck.NoSecretInHeap;

/**
 * @Transactional through Spring's MongoTransactionManager on seclume's
 * driver, against the replica set: both writes, or neither.
 */
@SpringBootTest(classes = MongoApplication.class)
class SpringDataMongoTransactionsOnMongoTest {

    private static final String URL = Fixture.replicaSet();

    @Autowired
    PersonRepository people;

    @Autowired
    PersonService service;

    @BeforeAll
    static void needsTheReplicaSet() {
        Fixture.assumeThere(URL, "replica set fixture");
    }

    @DynamicPropertySource
    static void url(DynamicPropertyRegistry properties) {
        properties.add("seclume.mongo.url", () -> URL);
        properties.add("spring.mongodb.database", () -> "seclume_test");
        properties.add("spring.data.mongodb.database", () -> "seclume_test");
        properties.add("spring.data.mongodb.auto-index-creation", () -> "true");
    }

    @BeforeEach
    void empty() {
        people.deleteAll();
    }

    @Test
    void bothOrNeither() throws Exception {
        service.saveBoth(new Person("a@x", "A", 1, "X", List.of()),
                new Person("b@x", "B", 2, "X", List.of()));
        assertEquals(2, people.count());
        assertThrows(IllegalStateException.class, () -> service.saveThenFail(
                new Person("c@x", "C", 3, "X", List.of()),
                new Person("d@x", "D", 4, "X", List.of())));
        assertEquals(2, people.count(), "the failed transaction left documents behind");
        NoSecretInHeap.assertAbsent(Fixture.password());
    }
}
