package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.apache.kafka.common.security.authenticator.SaslClientCallbackHandler;
import org.apache.kafka.common.security.scram.ScramCredentialCallback;
import org.apache.kafka.common.security.scram.ScramLoginModule;
import org.apache.kafka.common.security.scram.internals.ScramFormatter;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;
import org.apache.kafka.common.security.scram.internals.ScramSaslServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The client against Kafka's own SCRAM server, in process: the broker's code
 * checks the proof, and the client checks the broker's signature. The
 * password is a constant here because the server side needs it to make the
 * credential - the heap is examined against a real broker, in
 * {@link LocalKafkaScramTest}.
 */
class ScramAgainstKafkaTest {

    private static final String PASSWORD = "Kafka-9f3c1e,with=signs";
    private static final String USER = "orders,team=blue";

    @TempDir
    Path dir;

    @ParameterizedTest
    @ValueSource(strings = {"SCRAM-SHA-256", "SCRAM-SHA-512"})
    void kafkasServerAcceptsTheLogin(String mechanism) throws Exception {
        Subject subject = login(USER, secretFile(PASSWORD));
        SaslClient client = client(subject, mechanism);
        assertInstanceOf(ScramClient.class, client);
        SaslServer server = server(mechanism, PASSWORD);

        byte[] clientFirst = client.evaluateChallenge(new byte[0]);
        byte[] serverFirst = server.evaluateResponse(clientFirst);
        byte[] clientFinal = client.evaluateChallenge(serverFirst);
        byte[] serverFinal = server.evaluateResponse(clientFinal);
        assertTrue(server.isComplete());
        assertNull(client.evaluateChallenge(serverFinal));
        assertTrue(client.isComplete());
        client.dispose();
    }

    @ParameterizedTest
    @ValueSource(strings = {"SCRAM-SHA-256", "SCRAM-SHA-512"})
    void aWrongPasswordIsRefusedByKafka(String mechanism) throws Exception {
        Subject subject = login(USER, secretFile("not the password"));
        SaslClient client = client(subject, mechanism);
        SaslServer server = server(mechanism, PASSWORD);
        byte[] serverFirst = server.evaluateResponse(client.evaluateChallenge(new byte[0]));
        byte[] clientFinal = client.evaluateChallenge(serverFirst);
        SaslException refused = assertThrows(SaslException.class,
                () -> server.evaluateResponse(clientFinal));
        assertTrue(refused.getMessage().contains("Invalid client credentials"), refused.getMessage());
        assertFalse(server.isComplete());
        client.dispose();
    }

    /** A server that does not know the password cannot pass itself off as the broker. */
    @Test
    void aServerThatDoesNotKnowThePasswordIsRefused() throws Exception {
        Subject subject = login(USER, secretFile(PASSWORD));
        SaslClient client = client(subject, "SCRAM-SHA-512");
        SaslServer impostor = server("SCRAM-SHA-512", "a guess");
        byte[] serverFirst = impostor.evaluateResponse(client.evaluateChallenge(new byte[0]));
        byte[] clientFinal = client.evaluateChallenge(serverFirst);
        assertThrows(SaslException.class,
                () -> impostor.evaluateResponse(clientFinal));
        // Even had it answered, with the signature it could make:
        String forged = "v=" + java.util.Base64.getEncoder().encodeToString(new byte[64]);
        SaslException refused = assertThrows(SaslException.class, () -> client.evaluateChallenge(
                forged.getBytes(StandardCharsets.US_ASCII)));
        assertTrue(refused.getMessage().contains("could not prove"), refused.getMessage());
        client.dispose();
    }

    /** Kafka's own login module in the same JVM keeps working: its logins are not ours. */
    @Test
    void aLoginConfiguredOtherwiseIsLeftToKafka() throws Exception {
        login(USER, secretFile(PASSWORD));            // installs the provider in front
        Subject theirs = new Subject();
        ScramLoginModule kafka = new ScramLoginModule();  // registers Kafka's provider
        kafka.initialize(theirs, null, Map.of(), Map.of("username", USER, "password", PASSWORD));
        SaslClient client = client(theirs, "SCRAM-SHA-256");
        assertFalse(client instanceof ScramClient, "took a login it was not configured for");
        client.dispose();
    }

    @Test
    void aPasswordInTheConfigurationIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> new SeclumeScramLoginModule().initialize(new Subject(), null, Map.of(),
                        Map.of("username", USER, "password", "x")));
        assertTrue(refused.getMessage().contains("provider=file"), refused.getMessage());
    }

    @Test
    void theSubjectHoldsNoSecret() throws Exception {
        Subject subject = login(USER, secretFile(PASSWORD));
        assertTrue(subject.getPrivateCredentials().isEmpty());
        assertFalse(subject.toString().contains(PASSWORD));
    }

    private Path secretFile(String password) throws Exception {
        Path file = Files.createTempFile(dir, "kafka", ".pw");
        Files.writeString(file, password);
        return file;
    }

    private static Subject login(String user, Path secret) {
        Subject subject = new Subject();
        new SeclumeScramLoginModule().initialize(subject, null, Map.of(),
                Map.of("username", user, "provider", "file", "path", secret.toString()));
        return subject;
    }

    /** As Kafka's authenticator makes it: inside the subject, with Kafka's callback handler. */
    private static SaslClient client(Subject subject, String mechanism) throws Exception {
        SaslClientCallbackHandler callbacks = new SaslClientCallbackHandler();
        callbacks.configure(Map.of(), mechanism, List.of());
        return Subject.callAs(subject, () -> Sasl.createSaslClient(new String[] {mechanism},
                null, "kafka", "broker", Map.of(), callbacks));
    }

    private static SaslServer server(String mechanism, String password) throws Exception {
        ScramMechanism scram = ScramMechanism.forMechanismName(mechanism);
        var credential = new ScramFormatter(scram).generateCredential(password, 4096);
        return new ScramSaslServer(scram, Map.of(), (Callback[] callbacks) -> {
            for (Callback callback : callbacks) {
                if (callback instanceof ScramCredentialCallback c) {
                    c.scramCredential(credential);
                }
            }
        });
    }
}
