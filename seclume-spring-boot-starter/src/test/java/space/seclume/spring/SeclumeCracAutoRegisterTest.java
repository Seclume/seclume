package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import space.seclume.crac.SeclumeCrac;
import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * With seclume-crac on the class path, the starter registers what a
 * checkpoint needs: the process's part even in an application with no
 * DataSource - nothing else would load SeclumeCrac there - and every seclume
 * pool in the context, which CRaC otherwise refuses the checkpoint over.
 */
class SeclumeCracAutoRegisterTest {

    private static AnnotationConfigApplicationContext context(Class<?>... extra) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.register(SeclumeCracAutoConfiguration.class);
        if (extra.length > 0) {
            context.register(extra);
        }
        context.refresh();
        return context;
    }

    @Test
    void withoutADataSourceTheProcessIsRegistered() {
        try (AnnotationConfigApplicationContext context = context()) {
            assertTrue(context.containsBean("seclumeCracRegistration"));
            assertTrue(SeclumeCrac.isProcessRegistered());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class APool {
        @Bean(destroyMethod = "close")
        SeclumePool pool() {
            PoolSettings settings = new PoolSettings();
            settings.setName("crac-auto");
            settings.setMinimumIdle(0);
            settings.setConnectionTimeout(Duration.ofSeconds(1));
            return new SeclumePool(new org.springframework.jdbc.datasource.SimpleDriverDataSource(),
                    settings);
        }
    }

    @Test
    void everyPoolInTheContextIsRegistered() {
        try (AnnotationConfigApplicationContext context = context(APool.class)) {
            SeclumePool pool = context.getBean(SeclumePool.class);
            assertTrue(SeclumeCrac.isRegistered(pool), "the pool is not registered");
            SeclumeCrac.register(pool);                    // by hand as well: nothing changes
            assertTrue(SeclumeCrac.isRegistered(pool));
        }
    }
}
