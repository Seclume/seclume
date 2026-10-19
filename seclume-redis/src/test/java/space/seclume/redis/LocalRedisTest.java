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

    /** What a recording of {@code work} holds of the named events. */
    private static java.util.List<jdk.jfr.consumer.RecordedEvent> recorded(
            java.util.function.Consumer<jdk.jfr.Recording> work, String... names) throws Exception {
        Path file = Files.createTempFile("seclume-events", ".jfr");
        try (jdk.jfr.Recording recording = new jdk.jfr.Recording()) {
            for (String name : names) {
                recording.enable(name).withThreshold(java.time.Duration.ZERO);
            }
            recording.start();
            work.accept(recording);
            recording.stop();
            recording.dump(file);
            return jdk.jfr.consumer.RecordingFile.readAllEvents(file);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static jdk.jfr.consumer.RecordedEvent first(
            java.util.List<jdk.jfr.consumer.RecordedEvent> events, String name) {
        return events.stream().filter(e -> e.getEventType().getName().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no " + name + " in " + events));
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

    /**
     * The connection and the login against the real server, as Flight
     * Recorder events: the kind, the server, the mechanism - and that they
     * worked. Nothing of the password is in an event.
     */
    @Test
    void theConnectionAndTheLoginAreRecorded() throws Exception {
        java.util.List<jdk.jfr.consumer.RecordedEvent> events = recorded(recording -> {
            try (Jedis jedis = new Jedis(SeclumeRedisSocketFactory.of(url("rediss", tls, password,
                    "&tlsRootCert=" + ca.toString().replace('\\', '/'))))) {
                assertEquals("orders", jedis.aclWhoAmI());
            }
        }, "space.seclume.ConnectionOpen", "space.seclume.Authentication");
        jdk.jfr.consumer.RecordedEvent open = first(events, "space.seclume.ConnectionOpen");
        assertEquals("redis", open.getString("kind"));
        assertEquals(host + ":" + tls, open.getString("server"));
        assertTrue(open.getBoolean("succeeded"));
        jdk.jfr.consumer.RecordedEvent login = first(events, "space.seclume.Authentication");
        assertEquals("redis", login.getString("kind"));
        assertEquals("AUTH", login.getString("method"));
        assertTrue(login.getBoolean("succeeded"));
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
