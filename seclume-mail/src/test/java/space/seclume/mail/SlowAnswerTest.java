package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A server that answers a byte at a time, each just before the read timeout
 * would run out: no single read ever times out, and the timeout used to be
 * all there was. The login - greeting, capabilities, STARTTLS, handshake,
 * login - has {@code seclume.loginBudgetFactor} (3) times the read timeout
 * as a whole now. All before STARTTLS, where any server on the way can answer.
 */
@Timeout(60)
class SlowAnswerTest {

    private static Path password;

    @BeforeAll
    static void secret() throws IOException {
        password = Files.createTempFile("slow", ".pw");
        Files.writeString(password, "never-sent");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(password);
    }

    /** Sends an endless greeting line, a byte every 700 ms. */
    private static ServerSocket dribbling(String start) throws IOException {
        ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            try (Socket client = listener.accept()) {
                OutputStream out = client.getOutputStream();
                out.write(start.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                for (int i = 0; i < 100_000; i++) {
                    out.write('x');
                    out.flush();
                    Thread.sleep(700);
                }
            } catch (IOException | InterruptedException clientGone) {
                // the client gave up - what the test wants
            }
        });
        return listener;
    }

    private static String url(String scheme, ServerSocket server) {
        return scheme + "://localhost:" + server.getLocalPort() + "?user=reports&provider=file"
                + "&path=" + password.toString().replace('\\', '/') + "&timeout=1000";
    }

    private static void refusedInTime(long started, Exception refused) {
        long took = System.nanoTime() - started;
        assertTrue(took < 10_000_000_000L, "the login took " + took / 1_000_000 + " ms");
        assertTrue(String.valueOf(refused.getMessage()).contains("did not finish the login within 3 s"),
                refused.toString());
    }

    @Test
    void smtpGivesUpOnAGreetingThatNeverEnds() throws Exception {
        try (ServerSocket server = dribbling("220 ")) {
            long started = System.nanoTime();
            refusedInTime(started, assertThrows(MailException.class,
                    () -> SmtpConnection.open(MailSettings.of(url("smtp", server)))));
        }
    }

    @Test
    void imapGivesUpOnAGreetingThatNeverEnds() throws Exception {
        try (ServerSocket server = dribbling("* OK ")) {
            long started = System.nanoTime();
            refusedInTime(started, assertThrows(MailException.class,
                    () -> ImapLogin.open(MailSettings.of(url("imap", server)))));
        }
    }

    @Test
    void pop3GivesUpOnAGreetingThatNeverEnds() throws Exception {
        try (ServerSocket server = dribbling("+OK ")) {
            long started = System.nanoTime();
            refusedInTime(started, assertThrows(MailException.class,
                    () -> Pop3Login.open(MailSettings.of(url("pop3", server)))));
        }
    }

    @Test
    void theBudgetIsTheReadTimeoutTimesTheFactorAndNoneWithoutATimeout() {
        assertTrue(MailWire.loginBudget(0) == 0, "no timeout, no budget");
        assertTrue(MailWire.loginBudget(1000) == 3);
        assertTrue(MailWire.loginBudget(60_000) == 180);
        assertTrue(MailWire.loginBudget(1) == 1, "at least a second");
    }
}
