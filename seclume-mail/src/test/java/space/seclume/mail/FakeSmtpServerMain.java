package space.seclume.mail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

import javax.net.ssl.SSLContext;

/**
 * {@link FakeSmtpServer} in a JVM of its own, for the heap proof.
 *
 * <p>The server has to know the password to check it, and a JVM that knows it
 * has it on its heap. So this process makes the secrets up, writes them to
 * files for the client to read through its provider - and writes, next to
 * them, the exact forms they take on the wire (the base64 of the PLAIN,
 * LOGIN and XOAUTH2 arguments), so the test can search its own heap for
 * those as well. The test JVM only ever learns the paths.
 *
 * <pre>
 * args: keystore  directory
 * out:  READY smtpPort smtpsPort      (then it serves until stdin closes)
 * </pre>
 */
public final class FakeSmtpServerMain {

    private FakeSmtpServerMain() {
    }

    public static void main(String[] args) throws Exception {
        Path keystore = Path.of(args[0]);
        Path directory = Path.of(args[1]);
        SecureRandom random = new SecureRandom();
        byte[] password = ("pw-" + HexFormat.of().formatHex(random.generateSeed(12)))
                .getBytes(StandardCharsets.US_ASCII);
        byte[] token = ("ya29." + HexFormat.of().formatHex(random.generateSeed(24)))
                .getBytes(StandardCharsets.US_ASCII);
        String user = "reports";

        Files.write(directory.resolve("password"), password);
        Files.write(directory.resolve("token"), token);
        Files.write(directory.resolve("plain.b64"), Base64.getEncoder().encode(
                concat(new byte[] {0}, user.getBytes(StandardCharsets.US_ASCII), new byte[] {0},
                        password)));
        Files.write(directory.resolve("login.b64"), Base64.getEncoder().encode(password));
        Files.write(directory.resolve("xoauth2.b64"), Base64.getEncoder().encode(
                concat(("user=" + user + "\u0001auth=Bearer ").getBytes(StandardCharsets.US_ASCII),
                        token, new byte[] {1, 1})));

        SSLContext tls = TestPki.load(keystore).serverContext();
        try (FakeSmtpServer startTls = new FakeSmtpServer(tls, false);
             FakeSmtpServer implicit = new FakeSmtpServer(tls, true)) {
            for (FakeSmtpServer server : new FakeSmtpServer[] {startTls, implicit}) {
                server.user = user;
                server.password = password;
                server.token = token;
            }
            System.out.println("READY " + startTls.port() + " " + implicit.port());
            System.out.flush();
            while (System.in.read() >= 0) {
                // serve until the test closes our stdin
            }
            System.out.println("RECEIVED " + (startTls.received.size() + implicit.received.size())
                    + " LOGINS " + startTls.logins + implicit.logins);
        }
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            all.writeBytes(part);
        }
        return all.toByteArray();
    }
}
