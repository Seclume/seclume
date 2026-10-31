package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.apache.kafka.common.errors.SslAuthenticationException;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Against a real broker on SASL_SSL (see {@code proof/broker.sh}): PLAIN,
 * OAUTHBEARER and SCRAM, each producing and consuming through
 * {@link SeclumeSslEngineFactory}, a wrong password refused by the broker, a
 * broker whose CA is not named refused by the client - and then this JVM's
 * heap searched for the password and for the token, which the test never
 * read, only named by their files.
 *
 * <pre>
 *   seclume.kafka.host=broker.example.invalid
 *   seclume.kafka.securePort=19093
 *   seclume.kafka.passwordFile=.local-kafka-password   # the default
 * </pre>
 * The token and the broker's CA are expected beside the password file, as
 * {@code .local-kafka-token} and {@code .local-kafka-ca.pem}.
 *
 * <p>{@code -Dseclume.kafka.control=true} runs the control instead: Kafka's
 * own PlainLoginModule and the JDK's TLS, the password given as Kafka wants
 * it - and the same heap search finds it.
 */
class LocalKafkaSaslSslTest {

    private static String bootstrap;
    private static Path password;
    private static Path token;
    private static Path ca;

    @BeforeAll
    static void configured() {
        assumeTrue(TestHosts.isConfigured("kafka"), "no Kafka broker configured");
        TestHosts.Server broker = TestHosts.server("kafka", 19092);
        bootstrap = broker.host() + ":" + Integer.getInteger("seclume.kafka.securePort", 19093);
        password = find(broker.passwordFile());
        token = find(".local-kafka-token");
        ca = find(".local-kafka-ca.pem");
        assumeTrue(password != null && token != null && ca != null,
                "no password, token or CA file for the broker");
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

    @Test
    void plainOAuthBearerAndScramProduceAndConsumeAndNoSecretIsOnTheHeap() throws Exception {
        assumeTrue(!Boolean.getBoolean("seclume.kafka.control"), "the control runs instead");
        String topic = "seclume-" + UUID.randomUUID();
        try (Admin admin = Admin.create(plain(password))) {
            admin.createTopics(List.of(new NewTopic(topic, 1, (short) 1))).all().get();
        }
        roundTrip(plain(password), topic, "plain");
        roundTrip(oauthBearer(), topic, "oauthbearer");
        roundTrip(scram(), topic, "scram");
        try (Admin admin = Admin.create(oauthBearer())) {
            admin.deleteTopics(List.of(topic)).all().get();
        }
        NoSecretInHeap.assertAbsent(password);
        NoSecretInHeap.assertAbsent(token);
    }

    /**
     * Against the real broker, as Flight Recorder events: the PLAIN password
     * written into the SASL request, and the SCRAM login with its mechanism
     * and outcome.
     */
    @Test
    void theSecretWrittenInAndTheScramLoginAreRecorded() throws Exception {
        assumeTrue(!Boolean.getBoolean("seclume.kafka.control"), "the control runs instead");
        java.util.List<jdk.jfr.consumer.RecordedEvent> events = recorded(recording -> {
            for (Properties client : List.of(plain(password), scram())) {
                try (Admin admin = Admin.create(client)) {
                    admin.listTopics().names().get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new AssertionError(e);
                }
            }
        }, "space.seclume.SecretUse", "space.seclume.Authentication");
        jdk.jfr.consumer.RecordedEvent use = first(events, "space.seclume.SecretUse");
        assertEquals("kafka", use.getString("kind"));
        assertTrue(use.getString("target").endsWith(bootstrap.substring(bootstrap.lastIndexOf(':'))),
                use.getString("target"));
        jdk.jfr.consumer.RecordedEvent login = first(events, "space.seclume.Authentication");
        assertEquals("kafka", login.getString("kind"));
        assertEquals("SCRAM-SHA-512", login.getString("method"));
        assertTrue(login.getBoolean("succeeded"));
    }

    @Test
    void aWrongPasswordIsRefusedByTheBroker() throws Exception {
        assumeTrue(!Boolean.getBoolean("seclume.kafka.control"), "the control runs instead");
        Path wrong = Files.createTempFile("kafka", ".pw");
        try {
            Files.writeString(wrong, "not-the-password");
            try (Admin admin = Admin.create(plain(wrong))) {
                ExecutionException failed = assertThrows(ExecutionException.class,
                        () -> admin.listTopics().names().get());
                assertTrue(failed.getCause() instanceof SaslAuthenticationException,
                        failed.getCause().toString());
            }
        } finally {
            Files.delete(wrong);
        }
    }

    /** The broker's CA not named: the JVM's store does not know it, and nothing is sent. */
    @Test
    void aBrokerTheClientDoesNotTrustIsRefused() throws Exception {
        assumeTrue(!Boolean.getBoolean("seclume.kafka.control"), "the control runs instead");
        Properties p = plain(password);
        p.remove("ssl.truststore.type");
        p.remove("ssl.truststore.location");
        try (Admin admin = Admin.create(p)) {
            ExecutionException failed = assertThrows(ExecutionException.class,
                    () -> admin.listTopics().names().get());
            assertTrue(failed.getCause() instanceof SslAuthenticationException,
                    failed.getCause().toString());
        }
    }

    /** Kafka's own module on the JDK's TLS: the same search finds the password. */
    @Test
    void controlKafkasOwnPlainLoginLeavesThePasswordOnTheHeap() throws Exception {
        assumeTrue(Boolean.getBoolean("seclume.kafka.control"), "-Dseclume.kafka.control=true");
        Properties p = base();
        p.put("sasl.mechanism", "PLAIN");
        p.put("ssl.truststore.type", "PEM");
        p.put("ssl.truststore.location", ca.toString());
        p.put("sasl.jaas.config", "org.apache.kafka.common.security.plain.PlainLoginModule "
                + "required username=\"orders\" password=\"" + Files.readString(password).trim()
                + "\";");
        try (Admin admin = Admin.create(p)) {
            admin.listTopics().names().get();
        }
        assertThrows(AssertionError.class, () -> NoSecretInHeap.assertAbsent(password));
    }

    /**
     * Field encryption on the wire to a real broker: what the broker stores and
     * a consumer without the ring reads is ciphertext; with the ring, the value.
     */
    @Test
    void encryptedRecordsReachTheBrokerAsCiphertext() throws Exception {
        assumeTrue(!Boolean.getBoolean("seclume.kafka.control"), "the control runs instead");
        String topic = "seclume-encrypted-" + UUID.randomUUID();
        String value = "card 4111-1111-1111-1111 of customer 7";
        space.seclume.secret.SecretProvider key = new space.seclume.secret.SecretProvider() {
            @Override
            public int writeSecret(java.lang.foreign.MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(java.lang.foreign.ValueLayout.JAVA_BYTE, i, (byte) (i * 13 + 5));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
        try (Admin admin = Admin.create(plain(password));
             space.seclume.field.FieldKeys keys = space.seclume.field.FieldKeys.builder().key(1, key).build()) {
            admin.createTopics(List.of(new NewTopic(topic, 1, (short) 1))).all().get();
            try (KafkaProducer<String, String> producer = new KafkaProducer<>(plain(password),
                    new StringSerializer(), new EncryptingSerializer<>(new StringSerializer(), keys,
                            space.seclume.field.EncryptedColumn.Mode.RANDOMIZED))) {
                producer.send(new ProducerRecord<>(topic, "order", value)).get();
            }
            byte[] raw = consumeOne(topic, new org.apache.kafka.common.serialization.ByteArrayDeserializer());
            assertFalse(new String(raw, java.nio.charset.StandardCharsets.ISO_8859_1).contains("4111"),
                    "the broker holds the card number in the clear");
            assertEquals(value, consumeOne(topic, new DecryptingDeserializer<>(new StringDeserializer(), keys)));
            admin.deleteTopics(List.of(topic)).all().get();
        }
    }

    private static <T> T consumeOne(String topic, org.apache.kafka.common.serialization.Deserializer<T> values) {
        Properties consuming = new Properties();
        consuming.putAll(plain(password));
        consuming.put("group.id", "seclume-" + UUID.randomUUID());
        consuming.put("auto.offset.reset", "earliest");
        try (KafkaConsumer<String, T> consumer = new KafkaConsumer<>(consuming, new StringDeserializer(), values)) {
            consumer.subscribe(List.of(topic));
            for (int i = 0; i < 30; i++) {
                for (org.apache.kafka.clients.consumer.ConsumerRecord<String, T> record
                        : consumer.poll(Duration.ofSeconds(1))) {
                    return record.value();
                }
            }
        }
        throw new AssertionError("nothing to read on " + topic);
    }

    private static void roundTrip(Properties client, String topic, String value) throws Exception {
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(client,
                new StringSerializer(), new StringSerializer())) {
            producer.send(new ProducerRecord<>(topic, "order", value)).get();
        }
        Properties consuming = new Properties();
        consuming.putAll(client);
        consuming.put("group.id", "seclume-" + UUID.randomUUID());
        consuming.put("auto.offset.reset", "earliest");
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consuming,
                new StringDeserializer(), new StringDeserializer())) {
            consumer.subscribe(List.of(topic));
            List<String> values = new java.util.ArrayList<>();
            for (int i = 0; i < 30 && !values.contains(value); i++) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(1));
                records.forEach(record -> values.add(record.value()));
            }
            assertTrue(values.contains(value), "read " + values);
        }
    }

    private static Properties base() {
        Properties p = new Properties();
        p.put("bootstrap.servers", bootstrap);
        p.put("security.protocol", "SASL_SSL");
        p.put("request.timeout.ms", "10000");
        p.put("default.api.timeout.ms", "20000");
        return p;
    }

    private static Properties seclume() {
        Properties p = base();
        p.put("ssl.engine.factory.class", SeclumeSslEngineFactory.class.getName());
        p.put("ssl.truststore.type", "PEM");
        p.put("ssl.truststore.location", ca.toString());
        return p;
    }

    private static Properties plain(Path secret) {
        Properties p = seclume();
        p.put("sasl.mechanism", "PLAIN");
        p.put("sasl.jaas.config", "space.seclume.kafka.SeclumePlainLoginModule required "
                + "username=\"orders\" provider=\"file\" path=\"" + slashes(secret) + "\";");
        return p;
    }

    private static Properties oauthBearer() {
        Properties p = seclume();
        p.put("sasl.mechanism", "OAUTHBEARER");
        p.put("sasl.jaas.config", "space.seclume.kafka.SeclumeOAuthBearerLoginModule required "
                + "provider=\"file\" path=\"" + slashes(token) + "\";");
        return p;
    }

    private static Properties scram() {
        Properties p = seclume();
        p.put("sasl.mechanism", "SCRAM-SHA-512");
        p.put("sasl.jaas.config", "space.seclume.kafka.SeclumeScramLoginModule required "
                + "username=\"orders\" provider=\"file\" path=\"" + slashes(password) + "\";");
        return p;
    }

    private static String slashes(Path path) {
        return path.toString().replace('\\', '/');
    }
}
