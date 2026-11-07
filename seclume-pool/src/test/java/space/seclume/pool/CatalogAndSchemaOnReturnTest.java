package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * A borrower's {@code setCatalog} and {@code setSchema} end with its borrow.
 *
 * <p>The pool put back auto-commit, read-only, the isolation level and the
 * network timeout, but left catalog and schema where the last borrower took
 * them. The session reset does not cover them everywhere - MySQL's
 * {@code COM_RESET_CONNECTION} keeps the current database, and a foreign
 * driver may have no reset at all - so the next borrower got another
 * borrower's database or schema: with a schema per tenant, another tenant's
 * tables.
 */
class CatalogAndSchemaOnReturnTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setName("catalog-schema");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        return settings;
    }

    @Test
    void theNextBorrowerIsOnTheCatalogAndSchemaTheConnectionHad() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            try (Connection first = pool.getConnection()) {
                assertEquals(null, first.getSchema());
                StubDataSource.StubConnection stub = source.handedOut().get(0);
                stub.catalog = "shop";                  // what the server put it on
                stub.schema = "public";
            }
            try (Connection tenantA = pool.getConnection()) {
                tenantA.setSchema("tenant_a");
                tenantA.setCatalog("reports");
                tenantA.setSchema("tenant_a2");         // twice: the first one is what counts
                assertEquals("tenant_a2", source.handedOut().get(0).schema);
            }
            StubDataSource.StubConnection stub = source.handedOut().get(0);
            assertEquals("public", stub.schema, "lent on to the next borrower on tenant_a's schema");
            assertEquals("shop", stub.catalog, "lent on to the next borrower on another catalog");
            try (Connection next = pool.getConnection()) {
                assertEquals("public", next.getSchema());
                assertEquals("shop", next.getCatalog());
            }
            assertEquals(1, source.openedCount(), "the connection itself was kept");
        }
    }

    @Test
    void aBorrowThatLeavesThemAloneCostsNoQuestion() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            try (Connection c = pool.getConnection()) {
                StubDataSource.StubConnection stub = source.handedOut().get(0);
                stub.catalog = "shop";
                stub.schema = "public";
                c.createStatement().close();
            }
            // Changed behind the pool's back (a SET search_path, say): not the
            // pool's to know - the session reset's.
            source.handedOut().get(0).schema = "elsewhere";
            try (Connection c = pool.getConnection()) {
                c.createStatement().close();
            }
            assertEquals("elsewhere", source.handedOut().get(0).schema);
        }
    }

    @Test
    void whereNoCatalogWasChosenNoneCanBeChosenAgainAndTheConnectionGoes()
            throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            try (Connection c = pool.getConnection()) {
                c.setCatalog("reports");               // the stub starts on none
            }
            StubDataSource.StubConnection first = source.handedOut().get(0);
            assertTrue(first.closed.get(), "a connection on another catalog was kept");
            try (Connection c = pool.getConnection()) {
                assertEquals(null, c.getCatalog());
            }
            assertEquals(2, source.openedCount());
            assertSame(first, source.handedOut().get(0));
        }
    }
}
