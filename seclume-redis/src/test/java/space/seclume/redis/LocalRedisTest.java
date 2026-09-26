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

import redis.clients.jedis.ConnectionFactory;
import redis.clients.jedis.DefaultJedisClientConfig;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.UnifiedJedis;
import redis.clients.jedis.exceptions.JedisConnectionException;
import redis.clients.jedis.providers.PooledConnectionProvider;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Against a real Redis (see {@code proof/redis.sh}): logged in as an ACL user
 * over plain TCP and over TLS 1.3, one connection and a pool, a wrong password
 * refused, and afterwards this JVM's heap searched for the password - which
 * the test never read, only named by its file.
 *
 * <pre>
 *   seclume.redis.host=cache.example.invalid
 *   seclume.redis.port=16379          # plain
 *   seclume.redis.tlsPort=16380       # TLS 1.3
 *   seclume.redis.passwordFile=.local-redis-password   # the default
 * </pre>
 * The CA of the server's certificate is expected beside the password file,
 * as {@code .local-redis-ca.pem}.
 */
class LocalRedisTest {

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

    @Test
    void plainAndTlsOneConnectionAndAPoolAndThePasswordIsNotOnTheHeap() throws Exception {
        String key = "seclume-" + UUID.randomUUID();
        try (Jedis jedis = new Jedis(SeclumeRedisSocketFactory.of(
                url("redis", plain, password, "")))) {
            assertEquals("OK", jedis.set(key, "42 pencils"));
            assertEquals("orders", jedis.aclWhoAmI());
        }
        SeclumeRedisSocketFactory encrypted = SeclumeRedisSocketFactory.of(
                url("rediss", tls, password, "&tlsRootCert=" + ca.toString().replace('\\', '/')));
        try (Jedis jedis = new Jedis(encrypted)) {
            assertEquals("42 pencils", jedis.get(key));
        }
        try (UnifiedJedis pooled = redis.clients.jedis.RedisClient.builder()
                .connectionProvider(new PooledConnectionProvider(new ConnectionFactory(encrypted,
                        DefaultJedisClientConfig.builder().build())))
                .build()) {
            for (int i = 0; i < 20; i++) {
                pooled.incr(key + ":count");
            }
            assertEquals("20", pooled.get(key + ":count"));
            pooled.del(key, key + ":count");
        }
        NoSecretInHeap.assertAbsent(password);
    }

    @Test
    void aWrongPasswordIsRefused() throws Exception {
        Path wrong = Files.createTempFile("redis", ".pw");
        try {
            Files.writeString(wrong, "not-the-password");
            JedisConnectionException refused = assertThrows(JedisConnectionException.class,
                    () -> SeclumeRedisSocketFactory.of(url("redis", plain, wrong, ""))
                            .createSocket());
            assertTrue(refused.getMessage().contains("WRONGPASS"), refused.getMessage());
        } finally {
            Files.delete(wrong);
        }
    }

    /** Encrypted means checked: a CA the JVM does not know is refused unless it is named. */
    @Test
    void aServerTheJvmDoesNotTrustIsRefused() {
        JedisConnectionException refused = assertThrows(JedisConnectionException.class,
                () -> SeclumeRedisSocketFactory.of(url("rediss", tls, password, ""))
                        .createSocket());
        assertTrue(refused.getMessage().toLowerCase().contains("certif")
                || refused.getMessage().contains("PKIX"), refused.getMessage());
    }

    @Test
    void aPasswordInTheUrlIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeRedisSocketFactory.of("redis://orders:secret@" + host + ":1"));
        assertTrue(refused.getMessage().contains("provider="), refused.getMessage());
    }
}
