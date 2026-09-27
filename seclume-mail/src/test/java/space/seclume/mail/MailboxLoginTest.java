package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * seclume's own IMAP and POP3 logins, before Jakarta Mail is involved: every
 * mechanism, STARTTLS and implicit TLS, and the ways a login has to fail -
 * a wrong password, a refused token, a server that offers no encryption or
 * smuggles a reply in ahead of it.
 */
@Timeout(60)
class MailboxLoginTest {

    private static TestPki pki;
    private static Path passwordFile;
    private static Path tokenFile;

    @BeforeAll
    static void certificateAndSecrets() throws Exception {
        pki = TestPki.generate();
        passwordFile = Files.createTempFile("mailbox", ".pw");
        Files.writeString(passwordFile, "correct horse");
        tokenFile = Files.createTempFile("mailbox", ".token");
        Files.writeString(tokenFile, "ya29.test-token");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(passwordFile);
        Files.deleteIfExists(tokenFile);
    }

    private static MailSettings settings(String scheme, int port, String extra, Path secret) {
        return MailSettings.of(scheme + "://localhost:" + port + "?tlsPin=" + pki.pin()
                + "&user=reports" + extra + "&provider=file&path="
                + secret.toString().replace('\\', '/'));
    }

    private static MailSettings settings(String scheme, int port, String extra) {
        return settings(scheme, port, extra, passwordFile);
    }

    // ---- IMAP ------------------------------------------------------------------

    @Test
    void imapLogsInWithEveryMechanism() throws Exception {
        try (FakeImapServer server = new FakeImapServer(pki.serverContext(), false)) {
            server.mechanisms = List.of("PLAIN", "XOAUTH2");
            loggedIn(ImapLogin.open(settings("imap", server.port(), "")));
            loggedIn(ImapLogin.open(settings("imap", server.port(), "&auth=xoauth2", tokenFile)));
            server.mechanisms = List.of("XOAUTH2");
            loggedIn(ImapLogin.open(settings("imap", server.port(), "")));        // LOGIN, no PLAIN
            server.saslIr = false;
            server.mechanisms = List.of("PLAIN", "XOAUTH2");
            loggedIn(ImapLogin.open(settings("imap", server.port(), "&auth=plain")));
            loggedIn(ImapLogin.open(settings("imap", server.port(), "&auth=xoauth2", tokenFile)));
            assertEquals(List.of("PLAIN", "XOAUTH2", "LOGIN", "PLAIN", "XOAUTH2"), server.logins);
            assertTrue(server.commands.contains("STARTTLS"), server.commands.toString());
        }
    }

    @Test
    void imapOverImplicitTlsWithoutCapabilitiesInTheGreeting() throws Exception {
        try (FakeImapServer server = new FakeImapServer(pki.serverContext(), true)) {
            server.capabilityInGreeting = false;
            loggedIn(ImapLogin.open(settings("imaps", server.port(), "")));
            assertEquals(List.of("PLAIN"), server.logins);
            assertEquals(List.of("CAPABILITY", "AUTHENTICATE", "NOOP"), server.commands);
        }
    }

    @Test
    void imapRefusals() throws Exception {
        try (FakeImapServer server = new FakeImapServer(pki.serverContext(), false)) {
            server.password = "something else".getBytes();
            MailException wrong = assertThrows(MailException.class,
                    () -> ImapLogin.open(settings("imap", server.port(), "")));
            assertTrue(wrong.getMessage().contains("refused the login of reports"),
                    wrong.getMessage());
            server.saslIr = false;
            assertThrows(MailException.class,
                    () -> ImapLogin.open(settings("imap", server.port(), "&auth=login")));

            server.token = "another".getBytes();
            MailException token = assertThrows(MailException.class, () -> ImapLogin.open(
                    settings("imap", server.port(), "&auth=xoauth2", tokenFile)));
            assertTrue(token.getMessage().contains("401"), token.getMessage());

            server.loginDisabled = true;
            server.mechanisms = List.of("XOAUTH2");
            MailException disabled = assertThrows(MailException.class,
                    () -> ImapLogin.open(settings("imap", server.port(), "")));
            assertTrue(disabled.getMessage().contains("disabled LOGIN"), disabled.getMessage());
            assertEquals(List.of(), server.logins);
        }
    }

    @Test
    void imapNeverSpeaksInTheClear() throws Exception {
        try (FakeImapServer server = new FakeImapServer(pki.serverContext(), false)) {
            server.offerStartTls = false;
            MailException none = assertThrows(MailException.class,
                    () -> ImapLogin.open(settings("imap", server.port(), "")));
            assertTrue(none.getMessage().contains("does not offer STARTTLS"), none.getMessage());

            server.offerStartTls = true;
            server.injectAfterStartTls = true;
            assertThrows(MailException.class,
                    () -> ImapLogin.open(settings("imap", server.port(), "")));

            server.injectAfterStartTls = false;
            server.preauth = true;
            MailException preauth = assertThrows(MailException.class,
                    () -> ImapLogin.open(settings("imap", server.port(), "")));
            assertTrue(preauth.getMessage().contains("PREAUTH"), preauth.getMessage());
            assertEquals(List.of(), server.logins);
        }
    }

    // ---- POP3 ------------------------------------------------------------------

    @Test
    void pop3LogsInWithEveryMechanism() throws Exception {
        try (FakePop3Server server = new FakePop3Server(pki.serverContext(), false)) {
            loggedInPop3(Pop3Login.open(settings("pop3", server.port(), "")));
            loggedInPop3(Pop3Login.open(settings("pop3", server.port(), "&auth=xoauth2",
                    tokenFile)));
            loggedInPop3(Pop3Login.open(settings("pop3", server.port(), "&auth=login")));
            server.mechanisms = List.of();
            loggedInPop3(Pop3Login.open(settings("pop3", server.port(), "")));    // USER/PASS
            assertEquals(List.of("PLAIN", "XOAUTH2", "USER", "USER"), server.logins);
            assertEquals(List.of("correct horse", "correct horse"), server.passwordsSeen);
        }
    }

    @Test
    void pop3OverImplicitTls() throws Exception {
        try (FakePop3Server server = new FakePop3Server(pki.serverContext(), true)) {
            loggedInPop3(Pop3Login.open(settings("pop3s", server.port(), "")));
            assertEquals(List.of("CAPA", "AUTH", "STAT"), server.commands);
        }
    }

    @Test
    void pop3Refusals() throws Exception {
        try (FakePop3Server server = new FakePop3Server(pki.serverContext(), false)) {
            server.password = "something else".getBytes();
            MailException wrong = assertThrows(MailException.class,
                    () -> Pop3Login.open(settings("pop3", server.port(), "")));
            assertTrue(wrong.getMessage().contains("refused the login of reports"),
                    wrong.getMessage());
            assertThrows(MailException.class,
                    () -> Pop3Login.open(settings("pop3", server.port(), "&auth=login")));

            server.token = "another".getBytes();
            MailException token = assertThrows(MailException.class, () -> Pop3Login.open(
                    settings("pop3", server.port(), "&auth=xoauth2", tokenFile)));
            assertTrue(token.getMessage().contains("401"), token.getMessage());

            server.offerStartTls = false;
            MailException none = assertThrows(MailException.class,
                    () -> Pop3Login.open(settings("pop3", server.port(), "")));
            assertTrue(none.getMessage().contains("STLS"), none.getMessage());

            server.offerStartTls = true;
            server.injectAfterStartTls = true;
            assertThrows(MailException.class,
                    () -> Pop3Login.open(settings("pop3", server.port(), "")));
            assertEquals(List.of(), server.logins);
        }
    }

    @Test
    void aPasswordWithALineBreakIsNotSentAsPass() throws Exception {
        Path broken = Files.createTempFile("mailbox", ".pw");
        try (FakePop3Server server = new FakePop3Server(pki.serverContext(), false)) {
            Files.writeString(broken, "correct\r\nDELE 1");
            MailException e = assertThrows(MailException.class, () -> Pop3Login.open(
                    settings("pop3", server.port(), "&auth=login", broken)));
            assertTrue(e.getMessage().contains("line break"), e.getMessage());
            assertTrue(!server.commands.contains("DELE"), server.commands.toString());
        } finally {
            Files.deleteIfExists(broken);
        }
    }

    private static void loggedIn(MailWire wire) throws IOException {
        try (wire) {
            assertTrue(wire.encrypted());
            wire.writeLine("x NOOP");
            assertEquals("x OK NOOP completed", wire.readLine());
        }
    }

    private static void loggedInPop3(MailWire wire) throws IOException {
        try (wire) {
            assertTrue(wire.encrypted());
            wire.writeLine("STAT");
            assertTrue(wire.readLine().startsWith("+OK 0 "));
        }
    }
}
