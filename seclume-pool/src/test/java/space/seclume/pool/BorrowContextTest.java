package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.sql.Connection;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import space.seclume.BorrowContext;

/**
 * A context the borrower names is the one the connection gets, whatever the
 * thread would have said - and only for that borrow.
 */
class BorrowContextTest {

    @Test
    @SuppressWarnings("try")
    void aNamedContextIsTakenAndTheSupplierNotAsked() throws Exception {
        StubDataSource source = new StubDataSource();
        source.beforeReturn((StubDataSource.StubConnection newest) -> newest.takesContext = true);
        AtomicInteger asked = new AtomicInteger();
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setSessionContext(() -> {
            asked.incrementAndGet();
            return Map.of("app.tenant_id", "the-thread");
        });
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            try (Connection named = BorrowContext.with(Map.of("app.tenant_id", "acme"),
                    pool::getConnection)) {
                assertEquals(Map.of("app.tenant_id", "acme"),
                        source.handedOut().get(0).context);
            }
            assertEquals(0, asked.get());
            assertNull(BorrowContext.named(), "the name outlived its borrow");
            try (Connection plain = pool.getConnection()) {
                assertEquals(1, asked.get(), "without a name the supplier answers as before");
            }
        }
    }

    @Test
    void anInnerNameGivesWayToTheOuterOneAfter() throws Exception {
        BorrowContext.with(Map.of("k", "outer"), () -> {
            BorrowContext.with(Map.of("k", "inner"), () -> {
                assertEquals("inner", BorrowContext.named().get("k"));
                return null;
            });
            assertEquals("outer", BorrowContext.named().get("k"));
            return null;
        });
        assertNull(BorrowContext.named());
    }
}
