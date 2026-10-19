package space.seclume.mongoreactive;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;

import org.bson.Document;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.ReactiveMongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.reactive.TransactionalOperator;

import com.mongodb.reactivestreams.client.MongoClient;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import space.seclume.mongospring.Fixture;

/**
 * Spring Data MongoDB reactive on seclume's reactive client, on the replica set
 * (transactions and change streams need one).
 */
@SpringBootTest(classes = ReactiveApplication.class)
class SpringDataMongoReactiveOnMongoTest {

    private static final String URL = Fixture.replicaSet();
    private static final Duration WAIT = Duration.ofSeconds(30);

    @Autowired
    AccountRepository accounts;

    @Autowired
    ReactiveMongoTemplate template;

    @Autowired
    TransactionalOperator transactions;

    @Autowired
    MongoClient client;

    @BeforeAll
    static void needsTheServer() {
        Fixture.assumeThere(URL, "replica set fixture");
    }

    @DynamicPropertySource
    static void url(DynamicPropertyRegistry properties) {
        properties.add("seclume.mongo.url", () -> URL);
        properties.add("spring.mongodb.database", () -> "seclume_test");
        properties.add("spring.data.mongodb.database", () -> "seclume_test");
    }

    @BeforeEach
    void some() {
        accounts.deleteAll()
                .thenMany(accounts.saveAll(List.of(
                        new Account("a", "Ada", 100),
                        new Account("b", "Bob", 20),
                        new Account("c", "Cy", 300),
                        new Account("d", "Dee", 5))))
                .then()
                .block(WAIT);
    }

    @Test
    void theClientIsSeclumes() {
        assertTrue(client.getClass().getName().startsWith("space.seclume."),
                "Spring Boot made a client of its own: " + client.getClass());
    }

    @Test
    void derivedQueries() {
        StepVerifier.create(accounts.findByBalanceGreaterThan(10, Sort.by("balance")))
                .expectNextMatches(a -> a.owner().equals("Bob"))
                .expectNextMatches(a -> a.owner().equals("Ada"))
                .expectNextMatches(a -> a.owner().equals("Cy"))
                .verifyComplete();
        StepVerifier.create(accounts.findByOwner("Cy").map(Account::balance))
                .expectNext(300L).verifyComplete();
        StepVerifier.create(accounts.countByBalanceLessThan(50)).expectNext(2L).verifyComplete();
    }

    @Test
    void backpressureOneAtATime() {
        StepVerifier.create(accounts.findAll(Sort.by("owner")).map(Account::owner), 0)
                .expectSubscription()
                .expectNoEvent(Duration.ofMillis(200))
                .thenRequest(1).expectNext("Ada")
                .thenRequest(2).expectNext("Bob", "Cy")
                .thenCancel()
                .verify(WAIT);
    }

    @Test
    void theTemplate() {
        StepVerifier.create(template.updateFirst(Query.query(Criteria.where("owner").is("Dee")),
                new Update().inc("balance", 10), Account.class).map(r -> r.getModifiedCount()))
                .expectNext(1L).verifyComplete();
        StepVerifier.create(template.findDistinct(new Query(), "owner", Account.class,
                String.class).collectSortedList())
                .expectNext(List.of("Ada", "Bob", "Cy", "Dee")).verifyComplete();
        StepVerifier.create(template.aggregate(
                org.springframework.data.mongodb.core.aggregation.Aggregation.newAggregation(
                        org.springframework.data.mongodb.core.aggregation.Aggregation
                                .group().sum("balance").as("total")),
                Account.class, Document.class).map(d -> ((Number) d.get("total")).longValue()))
                .expectNext(435L).verifyComplete();
    }

    @Test
    void aTransactionCommits() {
        Mono<Void> transfer = moveMoney("c", "a", 50);
        StepVerifier.create(transactions.transactional(transfer)).verifyComplete();
        assertEquals(150, accounts.findById("a").block(WAIT).balance());
        assertEquals(250, accounts.findById("c").block(WAIT).balance());
    }

    @Test
    void aTransactionRollsBack() {
        Mono<Void> failing = moveMoney("c", "a", 50)
                .then(Mono.error(new IllegalStateException("changed my mind")));
        StepVerifier.create(transactions.transactional(failing))
                .verifyError(IllegalStateException.class);
        assertEquals(100, accounts.findById("a").block(WAIT).balance());
        assertEquals(300, accounts.findById("c").block(WAIT).balance());
    }

    @Test
    void aChangeStream() {
        Flux<String> changes = template.changeStream(Account.class)
                .watchCollection("zl_spring_accounts").listen()
                .map(event -> event.getBody().owner());
        StepVerifier.create(changes.take(1))
                .expectSubscription()
                .then(() -> Mono.delay(Duration.ofMillis(500))
                        .then(accounts.save(new Account("e", "Eve", 1)))
                        .subscribe())
                .expectNext("Eve")
                .verifyComplete();
    }

    private Mono<Void> moveMoney(String from, String to, long amount) {
        return accounts.findById(from).flatMap(a -> accounts.save(a.withBalance(
                a.balance() - amount)))
                .then(accounts.findById(to)).flatMap(a -> accounts.save(a.withBalance(
                        a.balance() + amount)))
                .then();
    }
}
