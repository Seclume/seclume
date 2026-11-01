package space.seclume.micronaut;

import java.sql.SQLException;

import javax.sql.DataSource;

import io.micronaut.context.event.BeanCreatedEvent;
import io.micronaut.context.event.BeanCreatedEventListener;
import io.micronaut.core.annotation.Order;
import io.micronaut.core.order.Ordered;
import jakarta.inject.Singleton;

import space.seclume.pool.SeclumePool;

/**
 * Keeps the {@link SeclumePool} bean the pool.
 *
 * <p>A library may replace every bean that is a {@code DataSource} with a
 * proxy of its own, and decides that by the class of the bean, not by the
 * types the bean is exposed as: Micronaut Data does, so that a
 * {@code DataSource} joins its transactions. The pool is a {@code DataSource},
 * and its {@code SeclumePool} bean would then be Micronaut's proxy - which is
 * not a {@code SeclumePool}, and fails whoever asks for one with a
 * {@code ClassCastException}. This listener runs after every other and hands
 * back the pool the proxy wraps. The {@code DataSource} bean of the same pool
 * is not touched: that one is meant to be wrapped.
 */
@Singleton
@Order(Ordered.LOWEST_PRECEDENCE)
final class SeclumePoolStaysThePool implements BeanCreatedEventListener<SeclumePool>, Ordered {

    @Override
    public SeclumePool onCreated(BeanCreatedEvent<SeclumePool> event) {
        // As Object: after another listener, the bean need not be what its type says.
        Object bean = event.getBean();
        return pool(bean, event.getBeanIdentifier().getName());
    }

    /** The pool itself, or the pool a wrapping {@code DataSource} holds. */
    static SeclumePool pool(Object bean, String name) {
        if (bean instanceof SeclumePool pool) {
            return pool;
        }
        if (bean instanceof DataSource wrapper) {
            try {
                return wrapper.unwrap(SeclumePool.class);
            } catch (SQLException | RuntimeException e) {
                throw new IllegalStateException("the SeclumePool bean '" + name + "' was replaced by a "
                        + wrapper.getClass().getName() + " that does not unwrap to the pool", e);
            }
        }
        throw new IllegalStateException("the SeclumePool bean '" + name + "' was replaced by "
                + (bean == null ? "null" : "a " + bean.getClass().getName()));
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE;
    }

    @Override
    public String toString() {
        return "SeclumePoolStaysThePool";
    }
}
