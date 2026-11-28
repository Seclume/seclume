package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.util.Map;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import io.r2dbc.spi.ConnectionFactory;
import reactor.core.publisher.Mono;
import space.seclume.r2dbc.ReactiveSessionContext;

/**
 * The starter handed R2DBC the pool and nothing else: a tenant was whatever
 * the blocking SeclumeSessionContext read on an event loop. A
 * ReactiveSessionContext bean is what R2DBC connections are given now.
 */
class R2dbcSessionContextWiringTest {

    /** A DataSource that must not be reached: the context is resolved first. */
    private static final DataSource UNREACHED = (DataSource) Proxy.newProxyInstance(
            DataSource.class.getClassLoader(), new Class<?>[] {DataSource.class},
            (self, method, args) -> {
                throw new AssertionError("borrowed before the context was known: " + method);
            });

    @Test
    void aReactiveContextBeanIsWhatTheConnectionsAreGiven() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory(Map.of(
                "tenant", (ReactiveSessionContext) () ->
                        Mono.error(new IllegalStateException("no tenant in this request"))));
        ConnectionFactory factory = new SeclumeR2dbcAutoConfiguration().connectionFactory(
                UNREACHED, beans.getBeanProvider(ReactiveSessionContext.class),
                beans.getBeanProvider(SeclumeSessionContext.class));
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> Mono.from(factory.create()).block());
        assertEquals("no tenant in this request", refused.getMessage());
    }

    /**
     * A blocking context alone still starts - the R2DBC connections get no
     * context then, never one read on an event loop - and the log says so,
     * naming what to declare instead.
     */
    @Test
    void aBlockingContextAloneStillStartsAndSaysSo() {
        java.util.List<java.util.logging.LogRecord> said =
                new java.util.concurrent.CopyOnWriteArrayList<>();
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(
                SeclumeR2dbcAutoConfiguration.class.getName());
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            @Override
            public void publish(java.util.logging.LogRecord record) {
                said.add(record);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        log.addHandler(handler);
        try {
            StaticListableBeanFactory beans = new StaticListableBeanFactory(Map.of(
                    "tenant", (SeclumeSessionContext) Map::of));
            new SeclumeR2dbcAutoConfiguration().connectionFactory(UNREACHED,
                    beans.getBeanProvider(ReactiveSessionContext.class),
                    beans.getBeanProvider(SeclumeSessionContext.class));
            org.junit.jupiter.api.Assertions.assertTrue(said.stream().anyMatch(r ->
                    r.getLevel() == java.util.logging.Level.WARNING
                    && r.getMessage().contains("ReactiveSessionContext")),
                    "no warning naming ReactiveSessionContext: " + said.size() + " records");
            said.clear();
            new SeclumeR2dbcAutoConfiguration().connectionFactory(UNREACHED,
                    new StaticListableBeanFactory().getBeanProvider(ReactiveSessionContext.class),
                    new StaticListableBeanFactory().getBeanProvider(SeclumeSessionContext.class));
            org.junit.jupiter.api.Assertions.assertTrue(said.isEmpty(),
                    "a warning without any session context: " + said.size());
        } finally {
            log.removeHandler(handler);
        }
    }
}
