package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.NoSecretInHeap;

/**
 * The claim itself: after logging in every way this module knows - sending
 * over SMTP with PLAIN, LOGIN and XOAUTH2, reading over IMAP (AUTHENTICATE
 * and LOGIN) and POP3 (AUTH and USER/PASS), on its own and through Jakarta
 * Mail - neither the password nor the token is on this JVM's heap, and
 * neither are the base64 arguments they travelled in.
 *
 * <p>The server runs in a JVM of its own ({@link FakeMailServerMain}): it
 * makes the secrets up and writes them to files, and this JVM only ever holds
 * the paths - to hand to the secret provider, and to the heap search, which
 * runs in a third process. Nothing here reads a secret into a {@code String} -
 * until the end, where the control does exactly that and the search has to
 * find it.
 */
@Timeout(300)
class NoCredentialOnTheHeapTest {

    @Test
    void neitherPasswordNorTokenNorTheirWireFormsAreOnTheHeap() throws Exception {
        TestPki pki = TestPki.generate();
        Path directory = Files.createTempDirectory("seclume-mail-proof");
        Process server = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "-cp", System.getProperty("java.class.path"),
                FakeMailServerMain.class.getName(),
                pki.keystore.toString(), directory.toString()))
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try (BufferedReader out = new BufferedReader(new InputStreamReader(
                server.getInputStream(), StandardCharsets.UTF_8))) {
            String ready = out.readLine();
            assertTrue(ready != null && ready.startsWith("READY "), "the server said: " + ready);
            String[] ports = ready.split(" ");
            int smtp = Integer.parseInt(ports[1]);
            int smtps = Integer.parseInt(ports[2]);
            int imap = Integer.parseInt(ports[3]);
            int imaps = Integer.parseInt(ports[4]);
            int pop3 = Integer.parseInt(ports[5]);
            int pop3s = Integer.parseInt(ports[6]);

            Path password = directory.resolve("password");
            Path token = directory.resolve("token");
            String trust = "?tlsPin=" + pki.pin() + "&user=reports&provider=file&path=";
            SmtpConnection.MessageWriter body = w -> w.write(
                    "Subject: proof\r\n\r\nnothing secret in here\r\n"
                            .getBytes(StandardCharsets.US_ASCII));

            SeclumeMail.of("smtp://localhost:" + smtp + trust + slashes(password))
                    .send("reports@example.com", List.of("a@example.com"), body);
            SeclumeMail.of("smtp://localhost:" + smtp + trust + slashes(password) + "&auth=login")
                    .send("reports@example.com", List.of("b@example.com"), body);
            SeclumeMail.of("smtps://localhost:" + smtps + trust + slashes(token)
                            + "&auth=xoauth2")
                    .send("reports@example.com", List.of("c@example.com"), body);

            Session session = SeclumeMail.session(
                    "smtp://localhost:" + smtp + trust + slashes(password));
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("reports@example.com"));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress("d@example.com"));
            message.setSubject("proof through Jakarta Mail");
            message.setText("nothing secret in here either");
            Transport.send(message);

            Session reading = SeclumeMail.session(
                    "imap://localhost:" + imap + trust + slashes(password),
                    "pop3s://localhost:" + pop3s + trust + slashes(password) + "&auth=login");
            for (String protocol : List.of("imap", "pop3s")) {
                Store store = reading.getStore(protocol);
                store.connect();
                Folder inbox = store.getFolder("INBOX");
                inbox.open(Folder.READ_ONLY);
                assertEquals("proof", inbox.getMessage(1).getSubject());
                inbox.getMessage(1).writeTo(OutputStream.nullOutputStream());
                inbox.close(false);
                store.close();
            }
            SeclumeMail.of("imaps://localhost:" + imaps + trust + slashes(password)
                    + "&auth=login").store().close();
            SeclumeMail.of("imaps://localhost:" + imaps + trust + slashes(token)
                    + "&auth=xoauth2").store().close();
            SeclumeMail.of("pop3://localhost:" + pop3 + trust + slashes(token)
                    + "&auth=xoauth2").store().close();

            server.getOutputStream().close();
            assertTrue(server.waitFor(30, TimeUnit.SECONDS));
            List<String> tail = new ArrayList<>();
            for (String line; (line = out.readLine()) != null; ) {
                if (line.startsWith("RECEIVED")) {
                    tail.add(line);
                }
            }
            assertEquals(List.of("RECEIVED 4 LOGINS [PLAIN, LOGIN, PLAIN][XOAUTH2]"
                    + " IMAP [PLAIN][LOGIN, XOAUTH2] POP3 [XOAUTH2][USER]"), tail);

            for (String secret : List.of("password", "token", "plain.b64", "login.b64",
                    "xoauth2.b64")) {
                NoSecretInHeap.assertAbsent(directory.resolve(secret));
            }

            // The control: a search that cannot fail proves nothing. The AUTH PLAIN
            // argument as the String Jakarta Mail's own SMTP transport would build -
            // and now it has to be found.
            String leaked = Files.readString(directory.resolve("plain.b64")); // seclume-allow: the control, put on the heap on purpose
            AssertionError found = assertThrows(AssertionError.class,
                    () -> NoSecretInHeap.assertAbsent(directory.resolve("plain.b64")));
            assertTrue(found.getMessage().contains("the secret is on the heap"),
                    found.getMessage());
            Reference.reachabilityFence(leaked);
        } finally {
            server.destroyForcibly();
            try (var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    Files.deleteIfExists(file);
                }
            }
            Files.deleteIfExists(directory);
        }
    }

    private static String slashes(Path path) {
        return path.toString().replace('\\', '/');
    }
}
