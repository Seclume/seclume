package space.seclume.micronaut;

import java.sql.SQLException;

import javax.sql.DataSource;

import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;

import space.seclume.pool.PoolConfiguration;
import space.seclume.pool.SeclumePool;

/**
 * A {@link SeclumePool} for each {@link SeclumeDataSourceConfiguration}, under
 * its name, and a {@code javax.sql.DataSource} bean for each pool; {@code default}
 * is the primary one. Closed with the application context.
 *
 * <p>Two beans, the pool and the data source, of one instance: a library may
 * wrap every {@code DataSource} bean it finds - Micronaut Data does, in a proxy
 * of its own - and a pool exposed as a {@code DataSource} would then be that
 * proxy for whoever asks for a {@code SeclumePool}, which it is not. The
 * {@code SeclumePool} bean is typed as nothing else and stays the pool; the
 * {@code DataSource} bean is free to be wrapped.
 */
@Factory
public class SeclumeDataSourceFactory {

    @EachBean(SeclumeDataSourceConfiguration.class)
    @Bean(preDestroy = "close", typed = SeclumePool.class)
    public SeclumePool pool(SeclumeDataSourceConfiguration configuration) throws SQLException {
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

    /** The pool as the {@code DataSource} of the same name; closed with the pool, not here. */
    @EachBean(SeclumePool.class)
    @Bean(typed = DataSource.class)
    public DataSource dataSource(SeclumePool pool) {
        return pool;
    }
}
