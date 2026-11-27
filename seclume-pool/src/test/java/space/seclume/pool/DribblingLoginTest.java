package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.postgresql.jdbc.SeclumeDataSource;
import space.seclume.tck.DribblingServer;

/**
 * Two borrowers whose logins meet a server that answers a byte at a time:
 * each login held a slot of the pool for as long as the server liked. The
 * login budget ends them; both slots are free afterwards - the pool holds no
 * connection and lends again - and what the borrowers are told names the
 * budget, not a read that broke.
 */
@Timeout(60)
class DribblingLoginTest {

    @Test
    void aDribblingLoginFreesItsSlotAndSaysWhy() throws Exception {
        // 'N': no TLS (the default is prefer), then an authentication request
        // announced at 1000 bytes and sent a byte every 150 ms.
        try (DribblingServer server = new DribblingServer(new byte[] {'N', 'R', 0, 0, 0x03,
                (byte) 0xe8})) {
            SeclumeDataSource source = new SeclumeDataSource();
            source.setHost("127.0.0.1");
            source.setPort(server.port());
            source.setDatabase("app");
            source.setUser("app");
            source.setConnectTimeoutMillis(500);
            source.setSecretProvider(new space.seclume.tck.StaticSecretProvider("decoy-pw"));
            PoolSettings settings = new PoolSettings();
            settings.setName("dribbling");
            settings.setMaximumPoolSize(2);
            settings.setMinimumIdle(0);
            settings.setConnectionTimeout(Duration.ofSeconds(4));
            try (SeclumePool pool = new SeclumePool(source, settings)) {
                List<CompletableFuture<SQLException>> borrowers = new ArrayList<>();
                for (int i = 0; i < 2; i++) {
                    borrowers.add(CompletableFuture.supplyAsync(() -> {
                        try (Connection c = pool.getConnection()) {
                            return c.isClosed() ? null : null;
                        } catch (SQLException e) {
                            return e;
                        }
                    }));
                }
                for (CompletableFuture<SQLException> borrower : borrowers) {
                    SQLException failed = borrower.get(30, TimeUnit.SECONDS);
                    assertTrue(failed != null, "a dribbling login was let in");
                    assertTrue(String.valueOf(failed.getMessage()).contains("budget"),
                            "the borrower was not told about the budget: " + failed);
                }
                PoolStatistics after = pool.statistics();
                assertEquals(0, after.total(), "a slot is still held: " + after);
                assertEquals(0, after.active(), after.toString());
            }
        }
    }
}
