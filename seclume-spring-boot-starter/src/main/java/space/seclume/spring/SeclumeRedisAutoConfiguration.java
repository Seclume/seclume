package space.seclume.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import space.seclume.redis.SeclumeLettuce;

/**
 * Redis with the password off the heap, for Spring Data Redis:
 *
 * <pre>
 * seclume.redis.url=rediss://cache.example.com:6379?user=orders&amp;provider=file&amp;path=/run/secrets/redis
 * </pre>
 *
 * <p>A {@link LettuceConnectionFactory} whose Lettuce is given a placeholder
 * for the password, on client resources whose channels write the real one
 * in - over seclume's own TLS 1.3 for {@code rediss://} (see
 * {@link SeclumeLettuce}). Standalone and Sentinel. Spring Boot's own Redis
 * configuration steps aside, and makes {@code RedisTemplate},
 * {@code StringRedisTemplate}, repositories and the cache on this factory.
 * Jedis is not offered here: Spring Data Redis gives it no socket factory.
 *
 * <p>{@code spring.data.redis.password}, the Sentinel password and a
 * {@code spring.data.redis.url} with a password in it are refused while this
 * is on (see {@link InlineSecrets}).
 */
@AutoConfiguration(beforeName = "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration")
@ConditionalOnClass(name = {"space.seclume.redis.SeclumeLettuce",
    "org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory"})
@ConditionalOnProperty("seclume.redis.url")
public class SeclumeRedisAutoConfiguration {

    /** The resources, shut down after the connection factory that uses them. */
    @Bean(destroyMethod = "close")
    SeclumeLettuce.Prepared seclumeLettuce(Environment environment) {
        InlineSecrets.refuse(environment, "seclume.redis.url", new String[] {
            "spring.data.redis.password", "spring.data.redis.sentinel.password"},
            "spring.data.redis.url");
        return SeclumeLettuce.prepare(environment.getRequiredProperty("seclume.redis.url"));
    }

    @Bean
    @ConditionalOnMissingBean(RedisConnectionFactory.class)
    LettuceConnectionFactory redisConnectionFactory(SeclumeLettuce.Prepared lettuce) {
        LettuceClientConfiguration client = LettuceClientConfiguration.builder()
                .clientResources(lettuce.resources())
                .commandTimeout(lettuce.uri().getTimeout())
                .build();
        return new LettuceConnectionFactory(
                LettuceConnectionFactory.createRedisConfiguration(lettuce.uri()), client);
    }
}
