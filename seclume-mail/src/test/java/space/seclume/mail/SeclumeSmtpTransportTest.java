package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

import jakarta.mail.Address;
import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.Message;
import jakarta.mail.SendFailedException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * seclume-smtp as Jakarta Mail sees it: found by its protocol name, used by
 * {@code Transport.send}, a multipart message with an attachment, a partial
 * delivery as {@link SendFailedException} - and a password handed to Jakarta
 * Mail refused.
 */
@Timeout(60)
class SeclumeSmtpTransportTest {

    private static TestPki pki;
    private static Path passwordFile;

    @BeforeAll
    static void certificateAndSecret() throws Exception {
        pki = TestPki.generate();
        passwordFile = Files.createTempFile("smtp", ".pw");
        Files.writeString(passwordFile, "correct horse");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(passwordFile);
    }

    private static Session session(FakeSmtpServer server) {
        Properties props = new Properties();
        props.put(SeclumeSmtpTransport.URL_PROPERTY, "smtp://localhost:" + server.port()
                + "?tlsPin=" + pki.pin() + "&user=reports&provider=file&path="
                + passwordFile.toString().replace('\\', '/'));
        props.put("mail.transport.protocol.rfc822", SeclumeSmtpTransport.PROTOCOL);
        return Session.getInstance(props);
    }

    private static MimeMessage message(Session session, String... to) throws Exception {
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("reports@example.com"));
        for (String recipient : to) {
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient));
        }
        message.setSubject("Monthly figures");
        MimeBodyPart text = new MimeBodyPart();
        text.setText("See the attachment.\n.\nThat was a lone dot.", "UTF-8");
        MimeBodyPart attachment = new MimeBodyPart();
        attachment.setContent("a,b\n1,2\n", "text/csv");
        attachment.setFileName("figures.csv");
        message.setContent(new MimeMultipart(text, attachment));
        return message;
    }

    @Test
    void transportSendFindsTheProtocolAndDelivers() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            Session session = session(server);
            assertTrue(session.getTransport(SeclumeSmtpTransport.PROTOCOL)
                    instanceof SeclumeSmtpTransport);
            Transport.send(message(session, "team@example.com", "boss@example.com"));

            FakeSmtpServer.Received mail = server.received.get(0);
            assertEquals("reports@example.com", mail.from());
            assertEquals(List.of("team@example.com", "boss@example.com"), mail.recipients());
            assertTrue(mail.data().contains("Subject: Monthly figures"), mail.data());
            assertTrue(mail.data().contains("filename=figures.csv"), mail.data());
            assertTrue(mail.data().contains("\r\n.\r\nThat was a lone dot."), mail.data());
            assertEquals(List.of("PLAIN"), server.logins);
        }
    }

    @Test
    void theWayJavaMailSenderImplConnects() throws Exception {
        // Spring's JavaMailSenderImpl: getTransport(protocol), connect(host, port, user,
        // password) with whatever it was configured with - here nothing - then sendMessage.
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            Session session = session(server);
            MimeMessage message = message(session, "team@example.com");
            message.saveChanges();
            try (Transport transport = session.getTransport(SeclumeSmtpTransport.PROTOCOL)) {
                transport.connect(null, -1, null, null);
                transport.sendMessage(message, message.getAllRecipients());
                transport.sendMessage(message, message.getAllRecipients());
            }
            assertEquals(2, server.received.size());
            assertEquals(List.of("PLAIN"), server.logins, "one login, two messages");
        }
    }

    @Test
    void aPasswordGivenToJakartaMailIsRefused() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            Transport transport = session(server).getTransport(SeclumeSmtpTransport.PROTOCOL);
            AuthenticationFailedException refused = assertThrows(
                    AuthenticationFailedException.class,
                    () -> transport.connect("localhost", server.port(), "reports", "hunter2"));
            assertTrue(refused.getMessage().contains("takes no password"), refused.getMessage());
            assertTrue(server.commands.isEmpty(), "nothing reached the server");
        }
    }

    @Test
    void aPartialDeliveryIsASendFailedExceptionAfterTheRestGotIt() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            Session session = session(server);
            SendFailedException failed = assertThrows(SendFailedException.class,
                    () -> Transport.send(message(session, "team@example.com",
                            "nobody@example.com")));
            assertArrayEquals(new Address[] {new InternetAddress("nobody@example.com")},
                    failed.getInvalidAddresses());
            assertArrayEquals(new Address[] {new InternetAddress("team@example.com")},
                    failed.getValidSentAddresses());
            assertEquals(List.of("team@example.com"), server.received.get(0).recipients());
        }
    }

    @Test
    void aRefusedLoginIsAnAuthenticationFailure() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            server.password = "something else".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Session session = session(server);
            assertThrows(AuthenticationFailedException.class,
                    () -> Transport.send(message(session, "team@example.com")));
        }
    }
}
