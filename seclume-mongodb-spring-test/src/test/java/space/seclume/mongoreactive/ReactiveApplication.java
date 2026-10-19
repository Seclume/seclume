package space.seclume.mongoreactive;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.data.mongodb.ReactiveMongoDatabaseFactory;
import org.springframework.data.mongodb.ReactiveMongoTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;

import space.seclume.mongodb.driver.SeclumeMongoClients;
import space.seclume.mongodb.reactive.SeclumeMongoReactiveClients;

/**
 * A reactive Spring Boot application (Spring Data MongoDB reactive) whose
 * clients are seclume's: the reactive one for the application, the sync one so
 * that Boot makes no client of its own.
 */
@SpringBootApplication
public class ReactiveApplication {

    @Bean
    com.mongodb.reactivestreams.client.MongoClient reactiveMongoClient(Environment environment) {
        return SeclumeMongoReactiveClients.create(environment.getRequiredProperty(
                "seclume.mongo.url"));
    }

    @Bean
    com.mongodb.client.MongoClient mongoClient(Environment environment) {
        return SeclumeMongoClients.create(environment.getRequiredProperty("seclume.mongo.url"));
    }

    @Bean
    ReactiveMongoTransactionManager reactiveTransactionManager(
            ReactiveMongoDatabaseFactory factory) {
        return new ReactiveMongoTransactionManager(factory);
    }

    @Bean
    TransactionalOperator transactionalOperator(ReactiveMongoTransactionManager manager) {
        return TransactionalOperator.create(manager);
    }
}
