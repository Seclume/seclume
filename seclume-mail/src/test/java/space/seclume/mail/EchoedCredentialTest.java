package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A server that answers a line it does not like with that line - "unknown
 * command: ...", "cannot decode ..." - as some do. After the password was
 * written to it, from native memory, that answer holds the password: in the
 * form it was sent in, or decoded. The client made a {@code String} of every
 * reply line and the message of its exception of the refusal - the password on
 * the heap after all, and in whatever log the exception went to.
 *
 * <p>The password here is test data.
 */
@Timeout(60)
class EchoedCredentialTest {

    private static final String PASSWORD = "Zx9-correct-horse-battery";
    private static final String USER = "reports";

    private static TestPki pki;
    private static Path passwordFile;

    @BeforeAll
    static void certificateAndSecret() throws Exception {
        pki = TestPki.generate();
        passwordFile = Files.createTempFile("echo", ".pw");
        Files.writeString(passwordFile, PASSWORD);
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(passwordFile);
    }

    /** How the server gives back what it was sent. */
    private enum Echo { AS_SENT, DECODED }

    /** Speaks enough of the three protocols to be logged in to, and refuses by repeating. */
    private static final class Echoing extends FakeLineServer {
        private final String protocol;
        private final Echo echo;
        /** The mechanisms offered; without PLAIN the protocols' own logins are used. */
        private final boolean plain;
        final List<String> echoed = new CopyOnWriteArrayList<>();

        Echoing(SSLContext tls, String protocol, Echo echo, boolean plain) throws IOException {
            super(tls, true, "echoing-" + protocol);
            this.protocol = protocol;
            this.echo = echo;
            this.plain = plain;
        }

        @Override
        void serve(Connection c) throws IOException {
            switch (protocol) {
                case "smtps" -> smtp(c);
                case "pop3s" -> pop3(c);
                default -> imap(c);
            }
        }

        private String shown(String line) {
            String shown = line;
            if (echo == Echo.DECODED) {
                String last = line.substring(line.lastIndexOf(' ') + 1);
                try {
                    shown = new String(Base64.getDecoder().decode(last), StandardCharsets.UTF_8)
                            .replace('\0', ' ');
                } catch (IllegalArgumentException notBase64) {
                    shown = line;
                }
            }
            echoed.add(shown);
            return shown;
        }

        private void smtp(Connection c) throws IOException {
            c.line("220 echo ESMTP");
            for (String line = c.readLine(); line != null; line = c.readLine()) {
                if (line.startsWith("EHLO")) {
                    c.line("250-echo");
                    c.line("250 AUTH " + (plain ? "PLAIN LOGIN" : "LOGIN"));
                } else if (line.equals("AUTH LOGIN")) {
                    c.line("334 VXNlcm5hbWU6");
                    c.readLine();
                    c.line("334 UGFzc3dvcmQ6");
                    c.line("535-5.7.8 not understood:");
                    c.line("535 5.7.8 " + shown(c.readLine()));
                } else if (line.startsWith("AUTH PLAIN")) {
                    c.line("535-5.7.8 not understood:");
                    c.line("535 5.7.8 " + shown(line));
                } else {
                    c.line("221 bye");
                    return;
                }
            }
        }

        private void pop3(Connection c) throws IOException {
            c.line("+OK echo POP3");
            for (String line = c.readLine(); line != null; line = c.readLine()) {
                if (line.equals("CAPA")) {
                    c.line("+OK");
                    c.line("USER");
                    if (plain) {
                        c.line("SASL PLAIN");
                    }
                    c.line(".");
                } else if (line.startsWith("USER")) {
                    c.line("+OK");
                } else if (line.startsWith("PASS") || line.startsWith("AUTH")) {
                    c.line("-ERR unknown command: " + shown(line));
                } else {
                    c.line("+OK bye");
                    return;
                }
            }
        }

        private void imap(Connection c) throws IOException {
            c.line("* OK [CAPABILITY IMAP4rev1" + (plain ? " AUTH=PLAIN SASL-IR" : "")
                    + "] echo IMAP");
            for (String line = c.readLine(); line != null; line = c.readLine()) {
                String tag = line.substring(0, line.indexOf(' '));
                if (line.contains(" LOGIN ")) {
                    int length = number(line.substring(line.indexOf('{') + 1,
                            line.indexOf('}')));
                    c.line("+ go ahead");
                    String password = new String(c.readBytes(length), StandardCharsets.UTF_8);
                    c.readLine();
                    c.line("* BAD cannot parse " + shown(password));
                    c.line(tag + " BAD cannot parse " + shown(password));
                } else if (line.contains(" AUTHENTICATE ")) {
                    c.line("* BAD cannot parse " + shown(line));
                    c.line(tag + " NO cannot parse " + shown(line));
                } else {
                    c.line(tag + " OK");
                }
            }
        }
    }

    private static String url(String scheme, Echoing server, String extra) {
        return scheme + "://localhost:" + server.port() + "?tlsPin=" + pki.pin() + "&user="
                + USER + extra + "&provider=file&path="
                + passwordFile.toString().replace('\\', '/');
    }

    private interface Login {
        void open(String url) throws Exception;
    }

    private static final Login SMTP = url -> SmtpConnection.open(MailSettings.of(url)).close();
    private static final Login IMAP = url -> ImapLogin.open(MailSettings.of(url)).close();
    private static final Login POP3 = url -> Pop3Login.open(MailSettings.of(url)).close();

    /** Logs in, is refused with an echo, and says what the exception holds of the password. */
    private static void refusedWithoutThePassword(String scheme, Login login, Echo echo,
            boolean plain, String extra) throws Exception {
        try (Echoing server = new Echoing(pki.serverContext(), scheme, echo, plain)) {
            MailException refused = assertThrows(MailException.class,
                    () -> login.open(url(scheme, server, extra)));
            String message = String.valueOf(refused.getMessage());
            assertFalse(server.echoed.isEmpty(), "the server was given nothing to repeat");
            String sent = String.join(" | ", server.echoed);
            // The server did send it back - or the test shows nothing.
            String encodedPlain = Base64.getEncoder().encodeToString(
                    ("\0" + USER + "\0" + PASSWORD).getBytes(StandardCharsets.UTF_8));
            String encodedPassword = Base64.getEncoder().encodeToString(
                    PASSWORD.getBytes(StandardCharsets.UTF_8));
            assertTrue(sent.contains(PASSWORD) || sent.contains(encodedPlain)
                    || sent.contains(encodedPassword), "what the server repeated: " + sent);
            // "\0reports\0" is nine bytes, twelve characters of base64 - public; the
            // password's part of the response starts right after them.
            for (String secret : List.of(PASSWORD, encodedPlain.substring(12), encodedPassword)) {
                for (int i = 0; i + 4 <= secret.length(); i++) {
                    String part = secret.substring(i, i + 4);
                    assertFalse(message.contains(part), "the exception holds '" + part
                            + "' of the credential: " + message);
                }
            }
            assertTrue(message.contains("*"), message);
            assertTrue(message.contains(USER), message);
        }
    }

    @Test
    void smtpPlainSentBackAsItWasSent() throws Exception {
        refusedWithoutThePassword("smtps", SMTP, Echo.AS_SENT, true, "");
    }

    @Test
    void smtpPlainSentBackDecoded() throws Exception {
        refusedWithoutThePassword("smtps", SMTP, Echo.DECODED, true, "");
    }

    @Test
    void smtpLoginSentBackAsItWasSent() throws Exception {
        refusedWithoutThePassword("smtps", SMTP, Echo.AS_SENT, false, "");
    }

    @Test
    void smtpLoginSentBackDecoded() throws Exception {
        refusedWithoutThePassword("smtps", SMTP, Echo.DECODED, false, "");
    }

    @Test
    void pop3PassSentBack() throws Exception {
        refusedWithoutThePassword("pop3s", POP3, Echo.AS_SENT, false, "");
    }

    @Test
    void pop3PlainSentBackAsItWasSentAndDecoded() throws Exception {
        refusedWithoutThePassword("pop3s", POP3, Echo.AS_SENT, true, "");
        refusedWithoutThePassword("pop3s", POP3, Echo.DECODED, true, "");
    }

    @Test
    void imapLoginSentBack() throws Exception {
        refusedWithoutThePassword("imaps", IMAP, Echo.AS_SENT, false, "");
    }

    @Test
    void imapPlainSentBackAsItWasSentAndDecoded() throws Exception {
        refusedWithoutThePassword("imaps", IMAP, Echo.AS_SENT, true, "");
        refusedWithoutThePassword("imaps", IMAP, Echo.DECODED, true, "");
    }

    @Test
    void afterTheLoginNothingIsKeptAndLinesAreReadAsTheyAre() throws Exception {
        try (FakePop3Server pop3 = new FakePop3Server(pki.serverContext(), true);
             FakeImapServer imap = new FakeImapServer(pki.serverContext(), true)) {
            pop3.password = PASSWORD.getBytes(StandardCharsets.UTF_8);
            imap.password = PASSWORD.getBytes(StandardCharsets.UTF_8);
            for (String auth : List.of("plain", "login")) {
                try (MailWire wire = Pop3Login.open(MailSettings.of("pop3s://localhost:"
                        + pop3.port() + "?tlsPin=" + pki.pin() + "&user=" + USER + "&auth=" + auth
                        + "&provider=file&path=" + passwordFile.toString().replace('\\', '/')))) {
                    assertFalse(wire.guarding(), "POP3 " + auth);
                }
                try (MailWire wire = ImapLogin.open(MailSettings.of("imaps://localhost:"
                        + imap.port() + "?tlsPin=" + pki.pin() + "&user=" + USER + "&auth=" + auth
                        + "&provider=file&path=" + passwordFile.toString().replace('\\', '/')))) {
                    assertFalse(wire.guarding(), "IMAP " + auth);
                }
            }
            assertEquals(2, pop3.logins.size(), pop3.logins.toString());
            assertEquals(2, imap.logins.size(), imap.logins.toString());
        }
    }
}
