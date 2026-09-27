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
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

/**
 * Spring's own {@code JavaMailSenderImpl}, configured the way FEATURES.md says:
 * a session from {@link SeclumeMail#session}, no host, no user name, no password.
 */
@Timeout(60)
class SpringJavaMailSenderTest {

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

    private static JavaMailSenderImpl sender(FakeSmtpServer server) {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setSession(SeclumeMail.session("smtp://localhost:" + server.port() + "?tlsPin="
                + pki.pin() + "&user=reports&provider=file&path="
                + passwordFile.toString().replace('\\', '/')));
        return sender;
    }

    @Test
    void simpleAndMimeMessages() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            JavaMailSenderImpl sender = sender(server);

            SimpleMailMessage simple = new SimpleMailMessage();
            simple.setFrom("reports@example.com");
            simple.setTo("team@example.com");
            simple.setSubject("simple");
            simple.setText("from a SimpleMailMessage");
            sender.send(simple);

            sender.send(mime -> {
                MimeMessageHelper helper = new MimeMessageHelper(mime, true, "UTF-8");
                helper.setFrom("reports@example.com");
                helper.setTo(new String[] {"a@example.com", "b@example.com"});
                helper.setSubject("with an attachment");
                helper.setText("<p>see attached</p>", true);
                helper.addAttachment("figures.csv",
                        new org.springframework.core.io.ByteArrayResource(
                                "a,b\n1,2\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            });

            assertEquals(2, server.received.size());
            assertTrue(server.received.get(0).data().contains("Subject: simple"));
            assertEquals(List.of("a@example.com", "b@example.com"),
                    server.received.get(1).recipients());
            assertTrue(server.received.get(1).data().contains("figures.csv"));
        }
    }

    @Test
    void aPasswordSetOnTheSenderIsRefused() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer(pki.serverContext(), false)) {
            JavaMailSenderImpl sender = sender(server);
            sender.setUsername("reports");
            sender.setPassword("hunter2");
            SimpleMailMessage simple = new SimpleMailMessage();
            simple.setFrom("reports@example.com");
            simple.setTo("team@example.com");
            simple.setText("x");
            MailAuthenticationException refused = assertThrows(
                    MailAuthenticationException.class, () -> sender.send(simple));
            // Spring says "Authentication failed" and keeps ours as the cause.
            assertTrue(refused.getCause().getMessage().contains("takes no password"),
                    String.valueOf(refused.getCause()));
            assertTrue(server.commands.isEmpty(), "nothing reached the server");
        }
    }
}
