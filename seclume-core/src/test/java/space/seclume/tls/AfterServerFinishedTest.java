package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tls.ScriptedTlsServer.Step;

/**
 * A handshake message after the server's Finished, still under the
 * handshake key - the flight the coverage-guided search produced on
 * 30.09.2026: {@code EE, Certificate, CertificateVerify, Finished,
 * Certificate}.
 *
 * <p>The server has authenticated itself by then, so this is not a bypass;
 * what matters is that nothing after Finished is accepted. Two shapes:
 *
 * <ul>
 *   <li>in the <b>same record</b> as Finished: RFC 8446 section 5.1 - a
 *       message before a key change has to end at a record boundary - so the
 *       handshake itself must fail;
 *   <li>in a <b>record of its own</b>: the client has moved to the
 *       application key and cannot tell before it reads, but the first read
 *       must fail - never deliver data past it.
 * </ul>
 */
@Timeout(60)
class AfterServerFinishedTest {

    private static final List<Step> TRAILING = List.of(Step.ENCRYPTED_EXTENSIONS,
            Step.CERTIFICATE, Step.CERTIFICATE_VERIFY, Step.FINISHED, Step.CERTIFICATE);
    private static final String HOSTNAME = "db.example.com";

    @Test
    void inTheSameRecordAsFinishedTheHandshakeFails() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        EncryptedFlight.Material material = EncryptedFlight.material();
        ScriptedTlsServer server = new ScriptedTlsServer(TRAILING, material.leaf(),
                material.key(), false, null);
        assertThrows(IOException.class,
                () -> ClientHandshake.connect(server, HOSTNAME, material.trust()).close());
    }

    @Test
    void inARecordOfItsOwnTheFirstReadFails() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        EncryptedFlight.Material material = EncryptedFlight.material();
        ScriptedTlsServer server = new ScriptedTlsServer(TRAILING, material.leaf(),
                material.key(), true, null);
        try (TlsConnection connection = ClientHandshake.connect(server, HOSTNAME,
                material.trust())) {
            assertThrows(IOException.class, () -> connection.read(ByteBuffer.allocate(64)));
        } catch (IOException refusedAlready) {
            // refusing at the handshake is as good
        }
    }
}
