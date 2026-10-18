package space.seclume.mongospring;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.data.mongodb.MongoDatabaseFactory;
import org.springframework.data.mongodb.MongoTransactionManager;

import com.mongodb.client.MongoClient;

import space.seclume.mongodb.driver.SeclumeMongoClients;

/**
 * A Spring Boot application as one would write it, with one change: the
 * {@link MongoClient} bean is seclume's. Spring Boot's own client
 * configuration steps back when a {@code MongoClient} bean exists, and
 * everything else - the template, the repositories, the transaction manager
 * - is Spring Data's, unchanged.
 */
@SpringBootApplication
public class MongoApplication {

    @Bean
    MongoClient mongoClient(Environment environment) {
        return SeclumeMongoClients.create(environment.getRequiredProperty("seclume.mongo.url"));
    }

    @Bean
    MongoTransactionManager transactionManager(MongoDatabaseFactory factory) {
        return new MongoTransactionManager(factory);
    }

    @Bean
    PersonService personService(PersonRepository people) {
        return new PersonService(people);
    }
}
