package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * {@code Statement.getConnection()} names the pool's handle, not the driver
 * connection behind it - and closing what it names gives the connection back.
 * Spring's {@code queryForStream} releases its connection exactly that way;
 * handed the driver's connection, it closed it behind the pool's back, and
 * the pool lost one connection per streamed query (found 26.09.2026: the
 * Spring suite's JVM waited ten seconds per pool at exit for connections that
 * could never come back).
 */
@Timeout(120)
class StatementsNameTheHandleTest {

    static java.util.List<SessionResetTest.Db> databases() {
        return SessionResetTest.databases();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void everyStatementAndTheMetadataNameTheHandle(SessionResetTest.Db db) throws Exception {
        for (boolean cached : new boolean[] {false, true}) {
            try (SeclumePool pool = new SeclumePool(
                    new SessionResetTest.UrlSource(SessionResetTest.url(db)), settings(cached))) {
                try (Connection handle = pool.getConnection();
                     Statement plain = handle.createStatement();
                     PreparedStatement prepared = handle.prepareStatement(db.identity());
                     ResultSet rows = prepared.executeQuery()) {
                    assertSame(handle, plain.getConnection(), "createStatement");
                    assertSame(handle, prepared.getConnection(), "prepareStatement, cached "
                            + cached);
                    if (!cached) {
                        assertSame(handle, rows.getStatement().getConnection(),
                                "the result's statement");
                    }
                    assertSame(handle, handle.getMetaData().getConnection(), "metadata");
                }
                // The way Spring gives a streamed query's connection back.
                Connection handle = pool.getConnection();
                PreparedStatement prepared = handle.prepareStatement(db.identity());
                try (ResultSet rows = prepared.executeQuery()) {
                    rows.next();
                }
                Connection named = prepared.getConnection();
                prepared.close();
                named.close();
                assertEquals(0, pool.statistics().active(),
                        "closing what the statement named did not give the connection back");
                // And the next borrower gets a working connection from it.
                try (Connection again = pool.getConnection();
                     Statement check = again.createStatement();
                     ResultSet rows = check.executeQuery(db.identity())) {
                    assertEquals(true, rows.next());
                }
            }
        }
    }

    private static PoolSettings settings(boolean cached) {
        PoolSettings settings = new PoolSettings();
        settings.setName("handle");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        if (!cached) {
            settings.setStatementCacheSize(0);
        }
        return settings;
    }
}
