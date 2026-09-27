package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Store;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Reading as Jakarta Mail sees it: {@code imap(s)} and {@code pop3(s)} in a
 * session from {@link SeclumeMail#session} are Angus Mail's stores on
 * seclume's logged-in sockets. A mailbox is opened, counted and read; Jakarta
 * Mail never logs in itself - IMAP sees no LOGIN or AUTHENTICATE from it, and
 * POP3 no USER or PASS - and a password handed to it is refused.
 */
@Timeout(60)
class SeclumeStoreTest {

    private static final String FIRST = "From: sender@example.com\r\nTo: reports@example.com\r\n"
            + "Subject: Monthly figures\r\n\r\nThe figures are in.\r\n.hidden dot\r\n";
    private static final String SECOND = "From: sender@example.com\r\nSubject: Again\r\n\r\n"
            + "Twice.\r\n";

    private static TestPki pki;
    private static Path passwordFile;

    @BeforeAll
    static void certificateAndSecret() throws Exception {
        pki = TestPki.generate();
        passwordFile = Files.createTempFile("store", ".pw");
        Files.writeString(passwordFile, "correct horse");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(passwordFile);
    }

    private static String url(String scheme, int port) {
        return scheme + "://localhost:" + port + "?tlsPin=" + pki.pin()
                + "&user=reports&provider=file&path=" + passwordFile.toString().replace('\\', '/');
    }

    @Test
    void imapReadsTheInboxThroughJakartaMail() throws Exception {
        try (FakeImapServer server = new FakeImapServer(pki.serverContext(), false)) {
            server.messages.add(FIRST);
            server.messages.add(SECOND);
            Session session = SeclumeMail.session(url("imap", server.port()));
            Store store = session.getStore();
            assertTrue(store instanceof SeclumeImapStore, store.getClass().getName());
            store.connect();
            try {
                Folder inbox = store.getFolder("INBOX");
                inbox.open(Folder.READ_ONLY);
                assertEquals(2, inbox.getMessageCount());
                Message first = inbox.getMessage(1);
                assertEquals("Monthly figures", first.getSubject());
                assertEquals(FIRST, raw(first));
                assertEquals(SECOND, raw(inbox.getMessage(2)));
                inbox.close(false);
            } finally {
                store.close();
            }
            // seclume logged in, once per connection Angus opened; Angus never did
            assertFalse(server.logins.isEmpty());
            assertEquals(server.logins.size(), server.commands.stream()
                    .filter(c -> c.equals("AUTHENTICATE") || c.equals("LOGIN")).count());
            assertTrue(server.commands.contains("EXAMINE"), server.commands.toString());
        }
    }

    @Test
    void imapsIsTheDefaultStoreAndStoreOpensIt() throws Exception {
        try (FakeImapServer server = new FakeImapServer(pki.serverContext(), true)) {
            server.messages.add(FIRST);
            Store store = SeclumeMail.of(url("imaps", server.port())).store();
            try {
                assertTrue(store.isConnected());
                Folder inbox = store.getFolder("INBOX");
                inbox.open(Folder.READ_ONLY);
                assertEquals("Monthly figures", inbox.getMessage(1).getSubject());
            } finally {
                store.close();
            }
            assertEquals(1, server.logins.size());
        }
    }

    @Test
    void pop3ReadsTheMaildropAndTheLoginNeverReachesTheServer() throws Exception {
        try (FakePop3Server server = new FakePop3Server(pki.serverContext(), false)) {
            server.messages.add(FIRST);
            server.messages.add(SECOND);
            Session session = SeclumeMail.session(url("pop3", server.port()));
            Store store = session.getStore("pop3");
            assertTrue(store instanceof SeclumePop3Store, store.getClass().getName());
            store.connect();
            try {
                Folder inbox = store.getFolder("INBOX");
                inbox.open(Folder.READ_ONLY);
                assertEquals(2, inbox.getMessageCount());
                Message first = inbox.getMessage(1);
                assertEquals("Monthly figures", first.getSubject());
                assertEquals(FIRST, raw(first));
                assertEquals(SECOND, raw(inbox.getMessage(2)));
                inbox.close(false);
            } finally {
                store.close();
            }
            assertEquals(1, server.logins.size());
            assertEquals("PLAIN", server.logins.get(0));
            // Angus's USER and PASS - with the placeholder - were answered by the socket
            assertEquals(1, server.commands.stream().filter(c -> c.equals("AUTH")).count());
            assertFalse(server.commands.contains("USER"), server.commands.toString());
            assertFalse(server.commands.contains("PASS"), server.commands.toString());
            assertTrue(server.commands.contains("RETR"), server.commands.toString());
            assertTrue(server.commands.contains("QUIT"), server.commands.toString());
        }
    }

    @Test
    void pop3sWithUserAndPassSendsTheRealPasswordOnce() throws Exception {
        try (FakePop3Server server = new FakePop3Server(pki.serverContext(), true)) {
            server.messages.add(FIRST);
            Session session = SeclumeMail.session(url("pop3s", server.port()) + "&auth=login");
            Store store = session.getStore();
            store.connect();
            try {
                Folder inbox = store.getFolder("INBOX");
                inbox.open(Folder.READ_ONLY);
                assertEquals(1, inbox.getMessageCount());
                inbox.close(false);
            } finally {
                store.close();
            }
            assertEquals(java.util.List.of("correct horse"), server.passwordsSeen);
        }
    }

    @Test
    void onlyThisSessionIsServedBySeclume() throws Exception {
        Session plain = Session.getInstance(new Properties());
        assertFalse(plain.getStore("imap") instanceof SeclumeImapStore);
        assertFalse(plain.getStore("pop3") instanceof SeclumePop3Store);
        Session both = SeclumeMail.session("smtp://localhost:1?user=u&provider=file&path=/nonexistent",
                "imaps://localhost:2?user=u&provider=file&path=/nonexistent",
                "pop3s://localhost:3?user=u&provider=file&path=/nonexistent");
        assertTrue(both.getStore() instanceof SeclumeImapStore);
        assertTrue(both.getStore("pop3s") instanceof SeclumePop3Store);
        assertTrue(both.getTransport() instanceof SeclumeTransport);
        // pop3 was not given a URL here: it stays Jakarta Mail's own
        assertFalse(both.getStore("pop3") instanceof SeclumePop3Store);
    }

    @Test
    void aPasswordGivenToJakartaMailIsRefused() throws Exception {
        try (FakeImapServer imap = new FakeImapServer(pki.serverContext(), true);
             FakePop3Server pop3 = new FakePop3Server(pki.serverContext(), true)) {
            Session session = SeclumeMail.session(url("imaps", imap.port()),
                    url("pop3s", pop3.port()));
            for (String protocol : new String[] {"imaps", "pop3s"}) {
                Store store = session.getStore(protocol);
                AuthenticationFailedException e = assertThrows(AuthenticationFailedException.class,
                        () -> store.connect("localhost", "reports", "hunter2"));
                assertTrue(e.getMessage().contains("takes no password"), e.getMessage());
            }
            assertTrue(imap.commands.isEmpty(), imap.commands.toString());
            assertTrue(pop3.commands.isEmpty(), pop3.commands.toString());
        }
    }

    @Test
    void aFailedLoginIsAnAuthenticationFailure() throws Exception {
        try (FakeImapServer server = new FakeImapServer(pki.serverContext(), true)) {
            server.password = "something else".getBytes(StandardCharsets.UTF_8);
            Store store = SeclumeMail.session(url("imaps", server.port())).getStore();
            MessagingException e = assertThrows(MessagingException.class, store::connect);
            assertTrue(String.valueOf(e.getMessage()).contains("refused the login of reports")
                    || String.valueOf(e.getCause()).contains("refused the login of reports"),
                    e + " / " + e.getCause());
        }
    }

    private static String raw(Message message) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        message.writeTo(out);
        return out.toString(StandardCharsets.UTF_8);
    }
}
