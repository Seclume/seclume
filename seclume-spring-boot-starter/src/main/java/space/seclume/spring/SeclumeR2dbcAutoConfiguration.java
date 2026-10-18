package space.seclume.spring;

import javax.sql.DataSource;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import io.r2dbc.spi.ConnectionFactory;
import space.seclume.pool.SeclumePool;
import space.seclume.r2dbc.SeclumeConnectionFactory;

/**
 * R2DBC over the seclume pool: with {@code seclume-r2dbc} on the class path,
 * the application's {@code ConnectionFactory} borrows from the same
 * {@code DataSource} that {@code seclume.datasources} configures.
 *
 * <p>So a reactive application gets what a blocking one gets - the password
 * never on the heap, its own TLS, and the session reset on every return,
 * because closing an R2DBC connection returns the pooled JDBC one. Spring
 * Boot's own R2DBC configuration steps aside: its {@code ConnectionFactory}
 * is conditional on there being none, and this one comes first. Spring's
 * {@code R2dbcTransactionManager} and {@code DatabaseClient} use it as they
 * would any other.
 *
 * <p>The placeholders are each database's own ({@code $1}, {@code ?},
 * {@code @name}, {@code :name}), read off the connection - a read-write split
 * over two databases works as well.
 */
@AutoConfiguration(after = SeclumeAutoConfiguration.class,
        beforeName = "org.springframework.boot.r2dbc.autoconfigure.R2dbcAutoConfiguration")
@ConditionalOnClass(name = {"io.r2dbc.spi.ConnectionFactory",
        "space.seclume.r2dbc.SeclumeConnectionFactory"})
@ConditionalOnBean(SeclumePool.class)
public class SeclumeR2dbcAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(ConnectionFactory.class)
    ConnectionFactory connectionFactory(DataSource dataSource) {
        return SeclumeConnectionFactory.over(dataSource);
    }
}
