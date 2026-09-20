package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.secret.FileSecretProvider;

/**
 * The complete login to a <b>real</b> Oracle instance.
 *
 * <p>This is the test Oracle owed the project. Every step before it could only
 * be cross-checked against the JCA or against a recording; here the server
 * itself says whether the derivation is right - and with a password it does not
 * forgive a single wrong byte in.
 *
 * <p>The password comes from a file, so over the path the library offers.
 * Without a reachable server this is skipped, not failed.
 */
class OracleLoginTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
    }

    private static String connectString() {
        return "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=" + HOST + ")(PORT=" + PORT + "))"
                + "(CONNECT_DATA=(SERVICE_NAME=" + SERVICE + ")"
                + "(CID=(PROGRAM=seclume)(HOST=seclume)(USER=seclume))))";
    }

    /** CONNECT, FAST_AUTH, and the password - and the server lets us in. */
    @Test
    void logsIn() throws Exception {
        try (NsChannel channel = NsChannel.connect(HOST, PORT, 10_000)) {
            int type = channel.sendConnect(connectString());
            Assumptions.assumeTrue(type == NsPacket.TYPE_ACCEPT,
                    "expected ACCEPT, got " + NsPacket.typeName(type));
            channel.readAccept();

            TtcAuth.Challenge challenge = TtcFastAuth.open(channel, "seclume", USER);
            assertTrue(challenge.is12c(), "unexpected verifier type");

            TtcLogin.phaseTwo(channel, USER, new FileSecretProvider(passwordFile, 256),
                    challenge, connectString());
            System.out.println("logged in to Oracle as " + USER);
        }
    }
}
