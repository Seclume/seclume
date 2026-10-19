package space.seclume.spring;

import java.io.IOException;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * RabbitMQ and NATS with the secret off the heap:
 *
 * <pre>
 * seclume.rabbitmq.url=amqps://mq.example.com/orders?user=app&amp;provider=file&amp;path=/run/secrets/rabbit
 * seclume.nats.url=tls://nats.example.com:4222?auth=creds&amp;provider=file&amp;path=/run/secrets/app.creds
 * </pre>
 *
 * <p>For RabbitMQ Spring AMQP's {@code CachingConnectionFactory} on
 * {@code SeclumeRabbit}'s client factory: Spring Boot's own Rabbit
 * configuration steps aside and makes its {@code RabbitTemplate}, listener
 * containers and admin on it. For NATS a {@code Connection}, for which Spring
 * Boot has nothing of its own.
 *
 * <p>{@code spring.rabbitmq.password}, and addresses with a password in them,
 * are refused while seclume configures RabbitMQ (see {@link InlineSecrets}).
 */
@AutoConfiguration(beforeName = "org.springframework.boot.amqp.autoconfigure.RabbitAutoConfiguration")
public class SeclumeMessagingAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"space.seclume.rabbitmq.SeclumeRabbit",
        "org.springframework.amqp.rabbit.connection.CachingConnectionFactory"})
    @ConditionalOnProperty("seclume.rabbitmq.url")
    static class Rabbit {

        @Bean
        @ConditionalOnMissingBean(org.springframework.amqp.rabbit.connection.ConnectionFactory.class)
        org.springframework.amqp.rabbit.connection.CachingConnectionFactory
                rabbitConnectionFactory(Environment environment) {
            InlineSecrets.refuse(environment, "seclume.rabbitmq.url",
                    new String[] {"spring.rabbitmq.password"}, "spring.rabbitmq.addresses");
            return new org.springframework.amqp.rabbit.connection.CachingConnectionFactory(
                    space.seclume.rabbitmq.SeclumeRabbit.connectionFactory(
                            environment.getRequiredProperty("seclume.rabbitmq.url")));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"space.seclume.nats.SeclumeNats", "io.nats.client.Connection"})
    @ConditionalOnProperty("seclume.nats.url")
    static class Nats {

        @Bean(destroyMethod = "close")
        @ConditionalOnMissingBean(io.nats.client.Connection.class)
        io.nats.client.Connection natsConnection(Environment environment)
                throws IOException, InterruptedException {
            return space.seclume.nats.SeclumeNats.connect(
                    environment.getRequiredProperty("seclume.nats.url"));
        }
    }
}
