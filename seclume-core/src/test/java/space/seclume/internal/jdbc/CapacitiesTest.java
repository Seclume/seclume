package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLTimeoutException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * The pool's capacity and idle-limit probes ran with no query timeout: a
 * server that never answered held the pool's slot for ever. Each probe is a
 * statement bounded by {@code seclume.pool.probeSeconds}.
 */
class CapacitiesTest {

    @Test
    void everyProbeIsBoundedAndATimeoutReadsAsUnknown() {
        AtomicInteger timeout = new AtomicInteger(-1);
        Statement statement = (Statement) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {Statement.class}, (self, method, args) -> switch (method.getName()) {
                    case "setQueryTimeout" -> {
                        timeout.set((Integer) args[0]);
                        yield null;
                    }
                    case "executeQuery" -> throw new SQLTimeoutException("no answer (decoy)");
                    default -> null;
                });
        Connection connection = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {Connection.class}, (self, method, args) ->
                        "createStatement".equals(method.getName()) ? statement : null);

        var capacity = Capacities.ask(connection, "select allowed", "select in_use");
        assertEquals(Capacities.PROBE_SECONDS, timeout.get(), "the probe had no deadline");
        assertEquals(-1, capacity.allowed());
        assertEquals(-1, capacity.inUse());
        assertEquals(null, Capacities.idleLimit(connection, "select idle",
                java.time.Duration.ofSeconds(1)));
    }
}
