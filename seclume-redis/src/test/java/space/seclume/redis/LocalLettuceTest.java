package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisConnectionException;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Lettuce against a real Redis (see {@code proof/redis.sh}): logged in as an
 * ACL user over plain TCP and over seclume's TLS 1.3, with RESP3's HELLO; a
 * connection killed by the server comes back and logs in again; a wrong
 * password and an untrusted server refused - and afterwards this JVM's heap
 * searched for the password, which the test never read.
 *
 * <p>{@code -Dseclume.redis.control=true} runs the control instead: Lettuce
 * given the password itself, and the same search finds it.
 */
class LocalLettuceTest {

    private static String host;
    private static int plain;
    private static int tls;
    private static Path password;
    private static Path ca;

    @BeforeAll
    static void configured() {
        assumeTrue(TestHosts.isConfigured("redis"), "no Redis configured");
        TestHosts.Server server = TestHosts.server("redis", 16379);
        host = server.host();
        plain = server.port();
        tls = Integer.getInteger("seclume.redis.tlsPort", 16380);
        password = find(server.passwordFile());
        ca = find(".local-redis-ca.pem");
        assumeTrue(password != null && ca != null, "no password file or CA for Redis");
    }

    private static Path find(String name) {
        for (Path candidate : new Path[] {Path.of(name), Path.of("..", name)}) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static String url(String scheme, int port, Path secret, String more) {
        return scheme + "://" + host + ":" + port + "?user=orders&provider=file&path="
                + secret.toString().replace('\\', '/') + more;
    }

    private static String tlsUrl(Path secret) {
        return url("rediss", tls, secret, "&tlsRootCert=" + ca.toString().replace('\\', '/'));
    }

    @Test
    void plainAndTlsAReconnectAndThePasswordIsNotOnTheHeap() throws Exception {
        assumeTrue(!Boolean.getBoolean("seclume.redis.control"), "the control runs instead");
        String key = "seclume-" + UUID.randomUUID();
        RedisClient overPlain = SeclumeLettuce.client(url("redis", plain, password, ""));
        try (StatefulRedisConnection<String, String> connection = overPlain.connect()) {
            RedisCommands<String, String> redis = connection.sync();
            assertEquals("OK", redis.set(key, "42 pencils"));
            assertEquals("orders", redis.aclWhoami());
        } finally {
            overPlain.shutdown();
        }
        RedisClient overTls = SeclumeLettuce.client(tlsUrl(password));
        try (StatefulRedisConnection<String, String> connection = overTls.connect()) {
            RedisCommands<String, String> redis = connection.sync();
            assertEquals("42 pencils", redis.get(key));
            assertTrue(redis.clientInfo().contains("user=orders"), redis.clientInfo());

            // The server drops the connection; Lettuce reconnects and logs in again.
            long id = redis.clientId();
            try {
                redis.clientKill(io.lettuce.core.KillArgs.Builder.id(id).skipme(false));
            } catch (RuntimeException closedUnderItsFeet) {
                // the answer may be lost with the connection
            }
            String again = null;
            for (int i = 0; i < 50 && again == null; i++) {
                try {
                    again = redis.get(key);
                } catch (RuntimeException reconnecting) {
                    Thread.sleep(100);
                }
            }
            assertEquals("42 pencils", again);
            assertTrue(redis.clientId() != id, "a new connection after the kill");
            redis.del(key);
        } finally {
            overTls.shutdown();
        }
        NoSecretInHeap.assertAbsent(password);
    }

    @Test
    void aWrongPasswordIsRefused() throws Exception {
        assumeTrue(!Boolean.getBoolean("seclume.redis.control"), "the control runs instead");
        Path wrong = Files.createTempFile("redis", ".pw");
        try {
            Files.writeString(wrong, "not-the-password");
            RedisClient client = SeclumeLettuce.client(tlsUrl(wrong));
            try {
                RedisConnectionException refused = assertThrows(RedisConnectionException.class,
                        client::connect);
                assertTrue(causes(refused).contains("WRONGPASS"), causes(refused));
            } finally {
                client.shutdown();
            }
        } finally {
            Files.delete(wrong);
        }
    }

    /** Encrypted means checked: a CA the JVM does not know is refused unless it is named. */
    @Test
    void aServerTheJvmDoesNotTrustIsRefused() {
        assumeTrue(!Boolean.getBoolean("seclume.redis.control"), "the control runs instead");
        RedisClient client = SeclumeLettuce.client(url("rediss", tls, password, ""));
        try {
            RedisConnectionException refused = assertThrows(RedisConnectionException.class,
                    client::connect);
            String why = causes(refused).toLowerCase();
            assertTrue(why.contains("certif") || why.contains("pkix") || why.contains("trust"),
                    why);
        } finally {
            client.shutdown();
        }
    }

    /** Lettuce given the password as it asks for it: the same search finds it. */
    @Test
    void controlLettuceWithThePasswordItselfLeavesItOnTheHeap() throws Exception {
        assumeTrue(Boolean.getBoolean("seclume.redis.control"), "-Dseclume.redis.control=true");
        RedisClient client = RedisClient.create(RedisURI.Builder.redis(host, plain)
                .withAuthentication("orders", Files.readString(password).trim().toCharArray())
                .build());
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            assertEquals("orders", connection.sync().aclWhoami());
        } finally {
            client.shutdown();
        }
        assertThrows(AssertionError.class, () -> NoSecretInHeap.assertAbsent(password));
    }

    private static String causes(Throwable failure) {
        StringBuilder chain = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            chain.append(t).append(" / ");
        }
        return chain.toString();
    }
}
