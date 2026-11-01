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
 * that joins its transactions - and the {@code DataSource} bean is free to be
 * wrapped. The {@code SeclumePool} bean is typed as nothing else and stays the
 * pool: a library that decides by the bean's class wraps it too, and
 * {@link SeclumePoolStaysThePool} takes the pool back out. Behind a wrapping
 * {@code DataSource} the pool is also {@code dataSource.unwrap(SeclumePool.class)}.
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
