package space.seclume.mongospring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.mongodb.client.MongoClient;

import space.seclume.mongodb.driver.SeclumeMongoClients;

/** Spring Data repositories on seclume's driver: derived queries, paging, @Query, @Aggregation. */
@SpringBootTest(classes = MongoApplication.class)
class SpringDataMongoRepositoriesOnMongoTest {

    private static final String URL = Fixture.standalone();

    @Autowired
    PersonRepository people;

    @Autowired
    MongoClient client;

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
        people.deleteAll();
        people.saveAll(List.of(
                new Person("ada@x", "Ada", 36, "London", List.of("math", "code")),
                new Person("bob@x", "Bob", 25, "Paris", List.of("code")),
                new Person("cy@x", "Cy", 41, "London", List.of("art")),
                new Person("dee@x", "Dee", 19, "Rome", List.of("code", "art")),
                new Person("eve@x", "Eve", 52, "London", List.of())));
    }

    @Test
    void theClientIsSeclumes() {
        assertTrue(client.getClass().getName().startsWith("space.seclume."),
                "Spring Boot made a client of its own: " + client.getClass());
    }

    @Test
    void derivedQueries() {
        assertEquals("Cy", people.findByEmail("cy@x").orElseThrow().getName());
        assertEquals(List.of("Ada", "Cy", "Eve"), people.findByAgeGreaterThanOrderByAgeAsc(30)
                .stream().map(Person::getName).toList());
        assertEquals(List.of("Ada", "Bob", "Dee"), people.findByTagsContaining("code").stream()
                .map(Person::getName).sorted().toList());
        assertEquals(3, people.countByAgeBetween(20, 45));
        assertEquals(List.of("Ada"), people.namesMatching("^A").stream().map(Person::getName)
                .toList());
    }

    @Test
    void pagingAndSorting() {
        Page<Person> first = people.findByAddressCity("London",
                PageRequest.of(0, 2, Sort.by("age").descending()));
        assertEquals(3, first.getTotalElements());
        assertEquals(2, first.getTotalPages());
        assertEquals(List.of("Eve", "Cy"), first.map(Person::getName).getContent());
        Page<Person> second = people.findByAddressCity("London", first.nextPageable());
        assertEquals(List.of("Ada"), second.map(Person::getName).getContent());
        assertEquals(5, people.findAll(Sort.by("name")).size());
    }

    @Test
    void anAggregationMethod() {
        var perCity = people.perCity().stream().collect(java.util.stream.Collectors.toMap(
                PersonRepository.CityCount::id, PersonRepository.CityCount::n));
        assertEquals(java.util.Map.of("London", 3, "Paris", 1, "Rome", 1), perCity);
    }

    /** The unique index Spring Data created, and the driver's error translated by Spring. */
    @Test
    void aDuplicateIsSpringsDuplicateKeyException() {
        assertThrows(DuplicateKeyException.class, () -> people.save(
                new Person("ada@x", "Another Ada", 1, "Oslo", List.of())));
    }

    /** @Version: a stale copy is refused, as Spring Data does it. */
    @Test
    void optimisticLocking() {
        Person ada = people.findByEmail("ada@x").orElseThrow();
        Person stale = people.findByEmail("ada@x").orElseThrow();
        ada.setAge(37);
        people.save(ada);
        stale.setAge(99);
        assertThrows(OptimisticLockingFailureException.class, () -> people.save(stale));
        assertEquals(37, people.findByEmail("ada@x").orElseThrow().getAge());
    }

    @Test
    void deletes() {
        assertEquals(2, people.deleteByAgeLessThan(30));
        assertEquals(3, people.count());
        people.deleteById(people.findByEmail("eve@x").orElseThrow().getId());
        assertEquals(2, people.count());
    }

    /** Not a Spring bean: the factory alone, for an application that builds its own. */
    @Test
    void theFactoryAloneWorksToo() {
        try (MongoClient own = SeclumeMongoClients.create(URL)) {
            assertEquals(5, own.getDatabase("seclume_test").getCollection("zl_spring_people")
                    .countDocuments());
        }
    }
}
