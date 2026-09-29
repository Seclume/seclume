package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * The commands Lettuce writes for its login, with the placeholder where the
 * password goes, come out with the password and the right bulk length - and
 * nothing else is touched.
 */
class RespPasswordRewriterTest {

    @TempDir
    Path dir;

    @Test
    void authWithAUser() throws Exception {
        String placeholder = RespPasswordRewriter.newPlaceholder();
        String sent = rewrite(placeholder, "s3cret-pw", "*3\r\n$4\r\nAUTH\r\n$6\r\norders\r\n$"
                + placeholder.length() + "\r\n" + placeholder + "\r\n");
        assertEquals("*3\r\n$4\r\nAUTH\r\n$6\r\norders\r\n$9\r\ns3cret-pw\r\n", sent);
    }

    @Test
    void helloWithAuthAndMoreCommandsAround() throws Exception {
        String placeholder = RespPasswordRewriter.newPlaceholder();
        String password = "p".repeat(123);                       // three digits
        String sent = rewrite(placeholder, password, "*1\r\n$4\r\nPING\r\n"
                + "*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\norders\r\n$"
                + placeholder.length() + "\r\n" + placeholder + "\r\n*2\r\n$3\r\nGET\r\n$1\r\nk\r\n");
        assertEquals("*1\r\n$4\r\nPING\r\n*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\n"
                + "orders\r\n$123\r\n" + password + "\r\n*2\r\n$3\r\nGET\r\n$1\r\nk\r\n", sent);
    }

    @Test
    void thePlaceholderAsAValueOfItsOwnIsNotReplaced() throws Exception {
        // Inside a longer value it is not the password argument: left as it is.
        String placeholder = RespPasswordRewriter.newPlaceholder();
        String value = "x" + placeholder;
        String command = "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$" + value.length() + "\r\n" + value + "\r\n";
        assertEquals(command, rewrite(placeholder, "pw", command));
    }

    @Test
    void anotherClientsPlaceholderIsNotOurs() throws Exception {
        String ours = RespPasswordRewriter.newPlaceholder();
        String theirs = RespPasswordRewriter.newPlaceholder();
        String command = "*2\r\n$4\r\nAUTH\r\n$" + theirs.length() + "\r\n" + theirs + "\r\n";
        RespPasswordRewriter rewriter = new RespPasswordRewriter(ours, file("pw"));
        assertFalse(rewriter.contains(ByteBuffer.wrap(command.getBytes(StandardCharsets.US_ASCII))));
        assertEquals(command, rewrite(ours, "pw", command));
    }

    private String rewrite(String placeholder, String password, String command) throws Exception {
        RespPasswordRewriter rewriter = new RespPasswordRewriter(placeholder, file(password));
        ByteBuffer plain = ByteBuffer.wrap(command.getBytes(StandardCharsets.US_ASCII));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (plain.hasRemaining()) {
            SeclumeSslEngine.Outgoing.Step step = rewriter.next(plain);
            if (step.replacement() == null) {
                byte[] same = new byte[step.unchanged()];
                plain.get(same);
                out.write(same);
            } else {
                try (SecretScope bytes = step.replacement()) {
                    byte[] secret = new byte[bytes.length()];
                    MemorySegment.copy(bytes.segment(), ValueLayout.JAVA_BYTE, 0, secret, 0,
                            secret.length);
                    out.write(secret);
                }
                plain.position(plain.position() + step.replaced());
            }
        }
        return out.toString(StandardCharsets.US_ASCII);
    }

    private space.seclume.secret.SecretProvider file(String secret) throws Exception {
        Path file = Files.createTempFile(dir, "redis", ".pw");
        Files.writeString(file, secret);
        return SecretProviders.of(Map.of("provider", "file", "path", file.toString()));
    }
}
