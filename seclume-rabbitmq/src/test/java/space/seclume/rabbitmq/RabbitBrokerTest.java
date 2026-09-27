package space.seclume.rabbitmq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.GetResponse;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

import space.seclume.tck.NoSecretInHeap;

/**
 * Against a real RabbitMQ with a TLS 1.3 listener: the official client and
 * Spring AMQP publish and receive through a connection that seclume logged
 * in, a wrong password is the broker's refusal, a password set on the client
 * is refused before it is sent - and the password is not on the heap.
 *
 * <p>Needs a broker: {@code SECLUME_RABBITMQ_PORT} (its TLS port),
 * {@code SECLUME_RABBITMQ_CERT} (its certificate, PEM) and
 * {@code SECLUME_RABBITMQ_PASSWORD_FILE} for the user {@code seclume}. CI sets
 * them; without them the test is skipped. {@code SECLUME_RABBITMQCTL} - a
 * command that drops every connection - adds the recovery test.
 */
@Timeout(120)
class RabbitBrokerTest {

    private static final String PORT = System.getenv("SECLUME_RABBITMQ_PORT");
    private static final String CERT = System.getenv("SECLUME_RABBITMQ_CERT");
    private static final String PASSWORD = System.getenv("SECLUME_RABBITMQ_PASSWORD_FILE");

    private static Path wrongPassword;

    @BeforeAll
    static void broker() throws IOException {
        Assumptions.assumeTrue(PORT != null && CERT != null && PASSWORD != null,
                "no RabbitMQ configured (SECLUME_RABBITMQ_PORT, _CERT, _PASSWORD_FILE)");
        wrongPassword = Files.createTempFile("rabbit", ".pw");
        Files.writeString(wrongPassword, "certainly-not-the-password");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        if (wrongPassword != null) {
            Files.deleteIfExists(wrongPassword);
        }
    }

    private static String url(String passwordFile) {
        return "amqps://localhost:" + PORT + "/?user=seclume&tlsRootCert="
                + CERT.replace('\\', '/') + "&provider=file&path="
                + passwordFile.replace('\\', '/');
    }

    /** The login is a SecretUse event - rabbitmq, plain - and no password. */
    @Test
    void theLoginIsRecorded() throws Exception {
        ConnectionFactory factory = SeclumeRabbit.connectionFactory(url(PASSWORD));
        var events = space.seclume.tck.Recorded.during(() -> factory.newConnection().close(),
                "space.seclume.SecretUse");
        assertEquals(1, events.size(), events.toString());
        assertEquals("rabbitmq", events.get(0).getString("kind"));
        assertEquals("plain", events.get(0).getString("mechanism"));
    }

    @Test
    void publishAndReceiveThroughTheOfficialClient() throws Exception {
        ConnectionFactory factory = SeclumeRabbit.connectionFactory(url(PASSWORD));
        String queue = "seclume-test-" + UUID.randomUUID();
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(queue, false, true, true, null);
            for (int i = 0; i < 3; i++) {
                channel.basicPublish("", queue, null, ("order " + i)
                        .getBytes(StandardCharsets.UTF_8));
            }
            for (int i = 0; i < 3; i++) {
                GetResponse got = null;
                for (int tries = 0; got == null && tries < 50; tries++) {
                    got = channel.basicGet(queue, true);
                    if (got == null) {
                        Thread.sleep(20);
                    }
                }
                assertNotNull(got);
                assertEquals("order " + i, new String(got.getBody(), StandardCharsets.UTF_8));
            }
            assertTrue(connection.isOpen());
        }
    }

    @Test
    void springAmqpOnTheSameFactory() throws Exception {
        CachingConnectionFactory spring = new CachingConnectionFactory(
                SeclumeRabbit.connectionFactory(url(PASSWORD)));
        try {
            RabbitTemplate template = new RabbitTemplate(spring);
            String queue = "seclume-spring-" + UUID.randomUUID();
            template.execute(channel -> channel.queueDeclare(queue, false, false, true, null));
            template.convertAndSend(queue, "hello from Spring");
            Object received = null;
            for (int tries = 0; received == null && tries < 50; tries++) {
                received = template.receiveAndConvert(queue, 100);
            }
            assertEquals("hello from Spring", received);
            template.execute(channel -> channel.queueDelete(queue));
        } finally {
            spring.destroy();
        }
    }

    /**
     * The broker drops every connection; the client's automatic recovery opens
     * a new one through the same socket factory - logged in again by seclume -
     * and the channel goes on. Needs {@code SECLUME_RABBITMQCTL}, the command
     * that reaches the broker.
     */
    @Test
    void automaticRecoveryLogsInAgain() throws Exception {
        String ctl = System.getenv("SECLUME_RABBITMQCTL");
        Assumptions.assumeTrue(ctl != null, "SECLUME_RABBITMQCTL not set");
        ConnectionFactory factory = SeclumeRabbit.connectionFactory(url(PASSWORD));
        factory.setNetworkRecoveryInterval(200);
        String queue = "seclume-recovery-" + UUID.randomUUID();
        try (Connection connection = factory.newConnection()) {
            Channel channel = connection.createChannel();
            channel.queueDeclare(queue, false, false, false, null);
            java.util.concurrent.CountDownLatch recovered = new java.util.concurrent.CountDownLatch(1);
            ((com.rabbitmq.client.Recoverable) connection).addRecoveryListener(
                    new com.rabbitmq.client.RecoveryListener() {
                        @Override
                        public void handleRecovery(com.rabbitmq.client.Recoverable r) {
                            recovered.countDown();
                        }

                        @Override
                        public void handleRecoveryStarted(com.rabbitmq.client.Recoverable r) {
                        }
                    });
            Process close = new ProcessBuilder(java.util.List.of(ctl.split(" ")))
                    .redirectErrorStream(true).start();
            close.getOutputStream().close();
            close.getInputStream().readAllBytes();
            assertEquals(0, close.waitFor());
            assertTrue(recovered.await(30, java.util.concurrent.TimeUnit.SECONDS),
                    "the connection did not recover");
            channel.basicPublish("", queue, null, "after recovery".getBytes(StandardCharsets.UTF_8));
            GetResponse got = null;
            for (int tries = 0; got == null && tries < 50; tries++) {
                got = channel.basicGet(queue, true);
                if (got == null) {
                    Thread.sleep(20);
                }
            }
            assertNotNull(got);
            assertEquals("after recovery", new String(got.getBody(), StandardCharsets.UTF_8));
            channel.queueDelete(queue);
        }
    }

    @Test
    void aWrongPasswordIsTheBrokersRefusal() {
        ConnectionFactory factory = SeclumeRabbit.connectionFactory(
                url(wrongPassword.toString()));
        Exception refused = assertThrows(Exception.class, factory::newConnection);
        assertTrue(refused instanceof com.rabbitmq.client.AuthenticationFailureException
                        || refused instanceof com.rabbitmq.client.PossibleAuthenticationFailureException,
                refused.toString());
    }

    @Test
    void aPasswordSetOnTheClientIsNotSent() {
        ConnectionFactory factory = SeclumeRabbit.connectionFactory(url(PASSWORD));
        factory.setPassword("a-password-in-a-string");
        Exception refused = assertThrows(Exception.class, factory::newConnection);
        assertTrue(String.valueOf(rootMessage(refused)).contains("is not sent"),
                String.valueOf(rootMessage(refused)));
    }

    @Test
    void thePasswordIsNotOnTheHeap() throws Exception {
        ConnectionFactory factory = SeclumeRabbit.connectionFactory(url(PASSWORD));
        for (int i = 0; i < 2; i++) {
            try (Connection connection = factory.newConnection()) {
                connection.createChannel().close();
            }
        }
        NoSecretInHeap.assertAbsent(Path.of(PASSWORD));

        String leaked = Files.readString(Path.of(PASSWORD)); // seclume-allow: the control, put on the heap on purpose
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(Path.of(PASSWORD)));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }

    private static String rootMessage(Throwable e) {
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage();
    }
}
