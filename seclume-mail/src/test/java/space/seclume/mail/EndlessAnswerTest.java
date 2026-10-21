package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A server that does not stop answering: each line within the limit a line
 * has, but lines without end - a {@code 250-} reply to EHLO, an IMAP
 * capability list, a POP3 {@code CAPA}. The client gives up after
 * {@value MailWire#MAX_REPLY_LINES} lines with a {@link MailException}
 * instead of collecting them until the heap is full. All before STARTTLS,
 * where any server on the way can answer.
 */
@Timeout(60)
class EndlessAnswerTest {

    private static Path password;

    @BeforeAll
    static void secret() throws IOException {
        password = Files.createTempFile("flood", ".pw");
        Files.writeString(password, "never-sent");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(password);
    }

    /** Greets, waits for the client's first line, then floods until the client goes. */
    private static ServerSocket flooding(String greeting, String first, String line)
            throws IOException {
        ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            try (Socket client = listener.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(
                         client.getInputStream(), StandardCharsets.US_ASCII))) {
                OutputStream out = client.getOutputStream();
                out.write((greeting + "\r\n").getBytes(StandardCharsets.US_ASCII));
                in.readLine();
                if (first != null) {
                    out.write((first + "\r\n").getBytes(StandardCharsets.US_ASCII));
                }
                byte[] again = (line + "\r\n").getBytes(StandardCharsets.US_ASCII);
                for (int i = 0; i < 1_000_000; i++) {
                    out.write(again);
                }
            } catch (IOException clientGone) {
                // the client gave up - what the test wants
            }
        });
        return listener;
    }

    private static String url(String scheme, ServerSocket server) {
        return scheme + "://localhost:" + server.getLocalPort() + "?user=reports&provider=file"
                + "&path=" + password.toString().replace('\\', '/');
    }

    private static void refusedForLength(Exception refused) {
        assertTrue(String.valueOf(refused.getMessage()).contains("more than "
                + MailWire.MAX_REPLY_LINES + " lines"), refused.toString());
    }

    @Test
    void smtpGivesUpOnAnEndlessEhloReply() throws Exception {
        try (ServerSocket server = flooding("220 smtp.example ESMTP", null, "250-X-PADDING")) {
            refusedForLength(assertThrows(MailException.class,
                    () -> SeclumeMail.of(url("smtp", server)).open()));
        }
    }

    @Test
    void imapGivesUpOnAnEndlessCapabilityList() throws Exception {
        try (ServerSocket server = flooding("* OK ready", null, "* CAPABILITY X-PADDING")) {
            refusedForLength(assertThrows(MailException.class,
                    () -> ImapLogin.open(MailSettings.of(url("imap", server)))));
        }
    }

    @Test
    void pop3GivesUpOnAnEndlessCapa() throws Exception {
        try (ServerSocket server = flooding("+OK ready", "+OK capabilities", "X-PADDING")) {
            refusedForLength(assertThrows(MailException.class,
                    () -> Pop3Login.open(MailSettings.of(url("pop3", server)))));
        }
    }
}
