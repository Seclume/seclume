package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * statement.getConnection() answered the driver's connection behind the
 * pool's handle. Closed there, it closed under the pool; kept, it outlived
 * the borrow and was the next borrower's session. Every statement the pool
 * lends answers the handle.
 */
class HandedStatementTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        return settings;
    }

    @Test
    void aStatementsConnectionIsThePoolsHandle() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            try (Connection handle = pool.getConnection()) {
                Statement plain = handle.createStatement();
                PreparedStatement prepared = handle.prepareStatement("select 1",
                        Statement.RETURN_GENERATED_KEYS);
                assertSame(handle, plain.getConnection());
                assertSame(handle, prepared.getConnection());
                plain.getConnection().close();                // gives the borrow back
            }
            assertFalse(source.handedOut().get(0).closed.get(),
                    "the driver's connection was closed under the pool");
            try (Connection again = pool.getConnection()) {
                assertTrue(again.isValid(1));
            }
            assertEquals(1, source.openedCount());
        }
    }

    @Test
    void everyMethodOfTheStatementInterfacesIsWrittenOut() {
        List<String> missing = new ArrayList<>();
        Class<?>[][] pairs = {{Statement.class, HandedStatement.class},
                {PreparedStatement.class, HandedPreparedStatement.class},
                {CallableStatement.class, HandedCallableStatement.class}};
        for (Class<?>[] pair : pairs) {
            for (Method wanted : pair[0].getMethods()) {
                if (Modifier.isStatic(wanted.getModifiers())) {
                    continue;
                }
                try {
                    pair[1].getDeclaredMethod(wanted.getName(), wanted.getParameterTypes());
                } catch (NoSuchMethodException absent) {
                    missing.add(pair[1].getSimpleName() + "." + wanted.getName());
                }
            }
        }
        assertTrue(missing.isEmpty(), "not written out - a default would answer: " + missing);
    }
}
