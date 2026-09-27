package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The SMTP client against {@link FakeSmtpServer}: every login, both ways of
 * encrypting, what DATA does to a message, a partial delivery - and the
 * refusals that keep a credential from going where it should not.
 */
@Timeout(60)
class SmtpConnectionTest {

    private static TestPki pki;
    private static Path passwordFile;
    private static Path tokenFile;

    @BeforeAll
    static void certificateAndSecrets() throws Exception {
        pki = TestPki.generate();
        passwordFile = Files.createTempFile("smtp", ".pw");
        Files.writeString(passwordFile, "correct horse");
        tokenFile = Files.createTempFile("smtp", ".token");
        Files.writeString(tokenFile, "ya29.test-token");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(passwordFile);
        Files.deleteIfExists(tokenFile);
    }

    private static String url(String scheme, FakeSmtpServer server, String more) {
        return scheme + "://localhost:" + server.port() + "?tlsPin=" + pki.pin() + more;
    }

    private static String login(Path secret) {
        return "&user=reports&provider=file&path=" + secret.toString().replace('\\', '/');
    }

    private static SmtpConnection.MessageWriter message(String text) {
        return out -> out.write(text.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void startTlsAndPlainByDefault() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            SmtpConnection.Sent sent = SeclumeMail.of(url("smtp", server, login(passwordFile)))
                    .send("reports@example.com", List.of("team@example.com"),
                            message("Subject: hello\r\n\r\nthe numbers\r\n"));
            assertEquals(List.of("team@example.com"), sent.accepted());
            assertTrue(sent.refused().isEmpty());
            assertTrue(sent.queued().contains("FAKE1"), sent.queued());
            assertEquals(List.of("PLAIN"), server.logins);
            assertTrue(server.commands.indexOf("STARTTLS") < server.commands.indexOf("AUTH PLAIN"),
                    server.commands.toString());
            FakeSmtpServer.Received mail = server.received.get(0);
            assertEquals("reports@example.com", mail.from());
            assertEquals("Subject: hello\r\n\r\nthe numbers\r\n", mail.data());
            assertTrue(mail.mailCommand().contains("BODY=8BITMIME"), mail.mailCommand());
        }
    }

    @Test
    void loginWhenThatIsAllTheServerOffers() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            server.mechanisms = List.of("LOGIN");
            SeclumeMail.of(url("smtp", server, login(passwordFile)))
                    .send("a@example.com", List.of("b@example.com"), message("x\r\n"));
            assertEquals(List.of("LOGIN"), server.logins);
        }
    }

    @Test
    void loginAskedForByName() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            SeclumeMail.of(url("smtp", server, login(passwordFile) + "&auth=login"))
                    .send("a@example.com", List.of("b@example.com"), message("x\r\n"));
            assertEquals(List.of("LOGIN"), server.logins);
        }
    }

    @Test
    void xoauth2WithAToken() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            SeclumeMail.of(url("smtp", server, login(tokenFile) + "&auth=xoauth2"))
                    .send("a@example.com", List.of("b@example.com"), message("x\r\n"));
            assertEquals(List.of("XOAUTH2"), server.logins);
        }
    }

    @Test
    void xoauth2RefusedSaysWhy() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            MailException refused = assertThrows(MailException.class, () -> SeclumeMail.of(
                    url("smtp", server, login(passwordFile) + "&auth=xoauth2")).open());
            assertEquals(535, refused.replyCode());
            assertTrue(refused.getMessage().contains("\"status\":\"401\""), refused.getMessage());
        }
    }

    @Test
    void implicitTls() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), true)) {
            try (SmtpConnection session = SeclumeMail.of(url("smtps", server,
                    login(passwordFile))).open()) {
                assertTrue(session.encrypted());
                assertFalse(session.extensions().containsKey("STARTTLS"));
                session.send("a@example.com", List.of("b@example.com"), message("one\r\n"));
                session.send("a@example.com", List.of("c@example.com"), message("two\r\n"));
            }
            assertEquals(2, server.received.size());
            assertEquals(List.of("PLAIN"), server.logins, "one login for both messages");
        }
    }

    @Test
    void aWrongPasswordIsRefusedWithTheServersReason() throws Exception {
        Path wrong = Files.createTempFile("smtp", ".wrong");
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            Files.writeString(wrong, "not it");
            MailException refused = assertThrows(MailException.class,
                    () -> SeclumeMail.of(url("smtp", server, login(wrong))).open());
            assertEquals(535, refused.replyCode());
            assertTrue(refused.getMessage().contains("credentials invalid"), refused.getMessage());
        } finally {
            Files.delete(wrong);
        }
    }

    @Test
    void noStartTlsOfferedMeansNothingIsSent() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            server.offerStartTls = false;
            MailException refused = assertThrows(MailException.class,
                    () -> SeclumeMail.of(url("smtp", server, login(passwordFile))).open());
            assertTrue(refused.getMessage().contains("does not offer STARTTLS"),
                    refused.getMessage());
            assertTrue(server.commands.stream().noneMatch(c -> c.startsWith("AUTH")),
                    server.commands.toString());
        }
    }

    @Test
    void bytesInjectedAfterStartTlsAreRefused() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            server.injectAfterStartTls = true;
            MailException refused = assertThrows(MailException.class,
                    () -> SeclumeMail.of(url("smtp", server, login(passwordFile))).open());
            assertTrue(refused.getMessage().contains("injected"), refused.getMessage());
            assertTrue(server.logins.isEmpty());
        }
    }

    @Test
    void aWrongCertificateIsRefusedBeforeAnyLogin() throws Exception {
        TestPki other = TestPki.generate();
        try (FakeSmtpServer server = new FakeSmtpServer(other.serverContext(), false)) {
            assertThrows(IOException.class,
                    () -> SeclumeMail.of(url("smtp", server, login(passwordFile))).open());
            assertTrue(server.logins.isEmpty());
            assertTrue(server.commands.stream().noneMatch(c -> c.startsWith("AUTH")));
        }
    }

    @Test
    void aRelayWithoutLoginInTheClear() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            server.requireAuth = false;
            try (SmtpConnection session = SeclumeMail.of(
                    "smtp://localhost:" + server.port() + "?tls=none").open()) {
                assertFalse(session.encrypted());
                session.send("a@example.com", List.of("b@example.com"), message("x\r\n"));
            }
            assertTrue(server.logins.isEmpty());
            assertFalse(server.commands.contains("STARTTLS"));
        }
    }

    @Test
    void dotsAreStuffedAndBareLineEndsBecomeCrlf() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            SeclumeMail.of(url("smtp", server, login(passwordFile))).send("a@example.com",
                    List.of("b@example.com"),
                    message(".leading dot\n..two\nbare cr\rline\r\n.\nno end"));
            // The server takes the stuffing off again: what arrives is the message
            // line for line, with CRLF - and the lone "." did not end DATA early.
            assertEquals(".leading dot\r\n..two\r\nbare cr\r\nline\r\n.\r\nno end\r\n",
                    server.received.get(0).data());
        }
    }

    @Test
    void someRecipientsRefusedTheRestGetIt() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            SmtpConnection.Sent sent = SeclumeMail.of(url("smtp", server, login(passwordFile)))
                    .send("a@example.com", List.of("b@example.com", "nobody@example.com"),
                            message("x\r\n"));
            assertEquals(List.of("b@example.com"), sent.accepted());
            assertEquals(Map.of("nobody@example.com", "5.1.1 no such user"), sent.refused());
            assertEquals(List.of("b@example.com"), server.received.get(0).recipients());
        }
    }

    @Test
    void allRecipientsRefusedSendsNothing() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            try (SmtpConnection session = SeclumeMail.of(
                    url("smtp", server, login(passwordFile))).open()) {
                assertThrows(MailException.class, () -> session.send("a@example.com",
                        List.of("nobody@example.com"), message("x\r\n")));
                // the session is still usable after the RSET
                session.send("a@example.com", List.of("b@example.com"), message("y\r\n"));
            }
            assertEquals(1, server.received.size());
        }
    }

    @Test
    void anUnicodeAddressNeedsSmtpUtf8() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            try (SmtpConnection session = SeclumeMail.of(
                    url("smtp", server, login(passwordFile))).open()) {
                assertThrows(MailException.class, () -> session.send("a@example.com",
                        List.of("jürgen@example.com"), message("x\r\n")));
            }
            server.smtpUtf8 = true;
            SeclumeMail.of(url("smtp", server, login(passwordFile))).send("a@example.com",
                    List.of("jürgen@example.com"), message("x\r\n"));
            assertTrue(server.received.get(0).mailCommand().endsWith(" SMTPUTF8"));
        }
    }
}
