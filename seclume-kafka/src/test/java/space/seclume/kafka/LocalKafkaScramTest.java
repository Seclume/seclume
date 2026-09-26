package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Against a real broker (see {@code proof/broker.sh}): a producer and a
 * consumer logged in with SCRAM-SHA-256 and SCRAM-SHA-512 through
 * {@link SeclumeScramLoginModule}, a wrong password refused by the broker,
 * and then the heap of this JVM searched for the password - which this test
 * never read, only named by its file.
 *
 * <pre>
 *   seclume.kafka.host=broker.example.invalid
 *   seclume.kafka.port=19092
 *   seclume.kafka.passwordFile=.local-kafka-password   # the default
 * </pre>
 */
class LocalKafkaScramTest {

    private static TestHosts.Server broker;
    private static Path password;

    @BeforeAll
    static void configured() {
        assumeTrue(TestHosts.isConfigured("kafka"), "no Kafka broker configured");
        broker = TestHosts.server("kafka", 19092);
        password = Path.of(broker.passwordFile());
        if (!Files.exists(password)) {
            password = Path.of("..", broker.passwordFile());
        }
        assumeTrue(Files.isReadable(password), "no password file for the broker");
    }

    @Test
    void producesAndConsumesWithBothMechanismsAndThePasswordIsNotOnTheHeap() throws Exception {
        String topic = "seclume-" + UUID.randomUUID();
        try (Admin admin = Admin.create(client("SCRAM-SHA-512", password))) {
            admin.createTopics(List.of(new NewTopic(topic, 1, (short) 1))).all().get();
        }
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(
                client("SCRAM-SHA-256", password), new StringSerializer(), new StringSerializer())) {
            producer.send(new ProducerRecord<>(topic, "order", "42 pencils")).get();
        }
        Properties consuming = client("SCRAM-SHA-512", password);
        consuming.put("group.id", "seclume-" + UUID.randomUUID());
        consuming.put("auto.offset.reset", "earliest");
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consuming,
                new StringDeserializer(), new StringDeserializer())) {
            consumer.subscribe(List.of(topic));
            String value = null;
            for (int i = 0; i < 30 && value == null; i++) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(1));
                if (!records.isEmpty()) {
                    value = records.iterator().next().value();
                }
            }
            assertEquals("42 pencils", value);
        }
        try (Admin admin = Admin.create(client("SCRAM-SHA-512", password))) {
            admin.deleteTopics(List.of(topic)).all().get();
        }
        NoSecretInHeap.assertAbsent(password);
    }

    @Test
    void aWrongPasswordIsRefusedByTheBroker() throws Exception {
        Path wrong = Files.createTempFile("kafka", ".pw");
        try {
            Files.writeString(wrong, "not-the-password");
            try (Admin admin = Admin.create(client("SCRAM-SHA-256", wrong))) {
                ExecutionException failed = assertThrows(ExecutionException.class,
                        () -> admin.listTopics().names().get());
                assertTrue(failed.getCause() instanceof SaslAuthenticationException,
                        failed.getCause().toString());
            }
        } finally {
            Files.delete(wrong);
        }
    }

    private static Properties client(String mechanism, Path secret) {
        Properties p = new Properties();
        p.put("bootstrap.servers", broker.host() + ":" + broker.port());
        p.put("security.protocol", "SASL_PLAINTEXT");
        p.put("sasl.mechanism", mechanism);
        p.put("sasl.jaas.config", "space.seclume.kafka.SeclumeScramLoginModule required "
                + "username=\"orders\" provider=\"file\" path=\""
                + secret.toAbsolutePath().toString().replace('\\', '/') + "\";");
        p.put("request.timeout.ms", "10000");
        p.put("default.api.timeout.ms", "20000");
        return p;
    }
}
