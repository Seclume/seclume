package space.seclume.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * MongoDB with the password off the heap:
 *
 * <pre>
 * seclume.mongodb.url=mongodb://app@db.example.com/?authSource=admin&amp;provider=file&amp;path=/run/secrets/mongo
 * spring.mongodb.database=shop
 * </pre>
 *
 * <p>The {@code MongoClient} is seclume's own driver when
 * {@code seclume-mongodb-driver} is on the class path, else the official
 * driver logged in on seclume's socket ({@code seclume-mongodb}); with
 * {@code seclume-mongodb-reactive} there is the reactive client as well.
 * Spring Boot's own Mongo configuration steps aside for them, and Spring
 * Data MongoDB - repositories, templates, transactions - runs on them.
 *
 * <p>{@code spring.mongodb.password}, and a {@code spring.mongodb.uri} with a
 * password in it, are refused while this is on (see {@link InlineSecrets}).
 */
@AutoConfiguration(beforeName = {
    "org.springframework.boot.mongodb.autoconfigure.MongoAutoConfiguration",
    "org.springframework.boot.mongodb.autoconfigure.MongoReactiveAutoConfiguration"})
@ConditionalOnProperty(SeclumeMongoAutoConfiguration.URL)
public class SeclumeMongoAutoConfiguration {

    static final String URL = "seclume.mongodb.url";

    private static String url(Environment environment) {
        InlineSecrets.refuse(environment, URL, new String[] {"spring.mongodb.password",
            "spring.data.mongodb.password"}, "spring.mongodb.uri", "spring.data.mongodb.uri");
        return environment.getRequiredProperty(URL);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "space.seclume.mongodb.driver.SeclumeMongoClients")
    static class OwnDriver {

        @Bean(destroyMethod = "close")
        @ConditionalOnMissingBean(com.mongodb.client.MongoClient.class)
        com.mongodb.client.MongoClient mongoClient(Environment environment) {
            return space.seclume.mongodb.driver.SeclumeMongoClients.create(url(environment));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"space.seclume.mongodb.SeclumeMongo",
        "com.mongodb.client.MongoClients"})
    @ConditionalOnMissingClass("space.seclume.mongodb.driver.SeclumeMongoClients")
    static class OfficialDriver {

        @Bean(destroyMethod = "close")
        @ConditionalOnMissingBean(com.mongodb.client.MongoClient.class)
        com.mongodb.client.MongoClient mongoClient(Environment environment) {
            return space.seclume.mongodb.SeclumeMongo.client(url(environment));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "space.seclume.mongodb.reactive.SeclumeMongoReactiveClients")
    static class Reactive {

        @Bean(destroyMethod = "close")
        @ConditionalOnMissingBean(com.mongodb.reactivestreams.client.MongoClient.class)
        com.mongodb.reactivestreams.client.MongoClient reactiveMongoClient(
                Environment environment) {
            return space.seclume.mongodb.reactive.SeclumeMongoReactiveClients.create(
                    url(environment));
        }
    }
}
