package space.seclume.micronaut;

import java.sql.SQLException;

import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;

import space.seclume.pool.PoolConfiguration;
import space.seclume.pool.SeclumePool;

/**
 * A {@link SeclumePool} - a {@code javax.sql.DataSource} - for each
 * {@link SeclumeDataSourceConfiguration}, under its name; {@code default} is
 * the primary one. Closed with the application context.
 */
@Factory
public class SeclumeDataSourceFactory {

    @EachBean(SeclumeDataSourceConfiguration.class)
    @Bean(preDestroy = "close")
    public SeclumePool dataSource(SeclumeDataSourceConfiguration configuration) throws SQLException {
        SeclumePool pool = PoolConfiguration.pool(configuration.getName(), configuration.getUrl(),
                configuration.getPool());
        if (pool.settings().isWarmup()) {
            try {
                pool.warmup();
            } catch (SQLException e) {
                pool.close();
                throw e;
            }
        }
        return pool;
    }
}
