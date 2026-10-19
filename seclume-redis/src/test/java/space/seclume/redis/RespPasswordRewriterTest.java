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

    @Test
    void sentinelAndMasterPlaceholdersEachWriteTheirOwnPassword() throws Exception {
        String masterPlaceholder = RespPasswordRewriter.newPlaceholder();
        String sentinelPlaceholder = RespPasswordRewriter.newPlaceholder();
        RespPasswordRewriter rewriter = new RespPasswordRewriter(
                masterPlaceholder, file("master-secret"),
                sentinelPlaceholder, file("sentinel-secret"),
                "localhost:26379");
        String sentinelAuth = "*3\r\n$4\r\nAUTH\r\n$8\r\nsentinel\r\n$"
                + sentinelPlaceholder.length() + "\r\n" + sentinelPlaceholder + "\r\n";
        String masterAuth = "*3\r\n$4\r\nAUTH\r\n$6\r\norders\r\n$"
                + masterPlaceholder.length() + "\r\n" + masterPlaceholder + "\r\n";
        assertEquals("*3\r\n$4\r\nAUTH\r\n$8\r\nsentinel\r\n$15\r\nsentinel-secret\r\n",
                rewriteWith(rewriter, sentinelAuth));
        assertEquals("*3\r\n$4\r\nAUTH\r\n$6\r\norders\r\n$13\r\nmaster-secret\r\n",
                rewriteWith(rewriter, masterAuth));
    }

    @Test
    void clusterAndSentinelUrlsAreParsedAndInlinePasswordsRefused() throws Exception {
        Path redisPw = Files.createTempFile(dir, "redis", ".pw");
        Path sentinelPw = Files.createTempFile(dir, "sentinel", ".pw");
        Files.writeString(redisPw, "pw1");
        Files.writeString(sentinelPw, "pw2");

        RedisUrl cluster = RedisUrl.parse("rediss://node-1:6380,node-2,[::1]:6381?user=orders"
                + "&provider=file&path=" + redisPw);
        assertEquals(java.util.List.of(
                new RedisUrl.Node("node-1", 6380),
                new RedisUrl.Node("node-2", 6379),
                new RedisUrl.Node("::1", 6381)), cluster.nodes());
        assertEquals("node-1", cluster.host());
        assertEquals(6380, cluster.port());
        org.junit.jupiter.api.Assertions.assertNull(cluster.sentinelMasterId());

        RedisUrl sentinel = RedisUrl.parse("rediss-sentinel://s1,s2:26380?sentinelMasterId=mymaster"
                + "&user=orders&provider=file&path=" + redisPw
                + "&sentinelUser=guard&sentinel-provider=file&sentinel-path=" + sentinelPw);
        assertEquals(java.util.List.of(
                new RedisUrl.Node("s1", 26379),
                new RedisUrl.Node("s2", 26380)), sentinel.nodes());
        assertEquals("mymaster", sentinel.sentinelMasterId());
        assertEquals("guard", sentinel.sentinelUser());
        org.junit.jupiter.api.Assertions.assertNotNull(sentinel.sentinelSecret());

        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> RedisUrl.parse("rediss-sentinel://s1:26379?provider=file&path=" + redisPw));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> RedisUrl.parse("rediss://s1:26379?sentinelMasterId=mymaster&sentinelPassword=bad"
                        + "&provider=file&path=" + redisPw));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> SeclumeLettuce.client("rediss://n1:6379,n2:6379?provider=file&path=" + redisPw));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> SeclumeLettuce.clusterClient(
                        "rediss://s1:26379?sentinelMasterId=mymaster&provider=file&path=" + redisPw));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> SeclumeRedisSocketFactory.of(
                        "rediss://n1:6379,n2:6379?provider=file&path=" + redisPw));
    }

    private String rewrite(String placeholder, String password, String command) throws Exception {
        return rewriteWith(new RespPasswordRewriter(placeholder, file(password)), command);
    }

    private String rewriteWith(RespPasswordRewriter rewriter, String command) throws Exception {
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
