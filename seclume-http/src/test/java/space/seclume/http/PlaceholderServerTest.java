package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.SecretScope;

/**
 * A placeholder's secret goes to one server. The socket writes the secret
 * into any request that carries the placeholder, and a client sends its
 * credentials where it is led - JGit to a submodule's host or after a
 * redirect, any client to a URL that came from somewhere else. So the
 * placeholder is bound to the first host and port it is written for, or to
 * the servers it was registered for, and elsewhere it goes as it is.
 */
class PlaceholderServerTest {

    private static final String SECRET = "ghp_0123456789abcdefSECRET";

    @TempDir
    Path dir;

    private String spec;

    @BeforeEach
    void aSecret() throws IOException {
        Path file = dir.resolve("token");
        Files.writeString(file, SECRET);
        spec = "provider=file&path=" + file.toString().replace('\\', '/');
    }

    private static String rewritten(String head, String server) throws IOException {
        try (SecretScope out = HttpFraming.rewrite(head.getBytes(StandardCharsets.ISO_8859_1),
                server)) {
            return new String(out.segment().asSlice(0, out.length()).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.ISO_8859_1);
        }
    }

    private static String bearer(String token) {
        return "GET /repo.git/info/refs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + token
                + "\r\n\r\n";
    }

    private static String basic(String user, String password) {
        return "GET /repo.git/info/refs HTTP/1.1\r\nHost: x\r\nAuthorization: Basic "
                + Base64.getEncoder().encodeToString((user + ":" + password)
                        .getBytes(StandardCharsets.UTF_8)) + "\r\n\r\n";
    }

    @Test
    void theFirstServerHasItAndAnotherGetsThePlaceholder() throws IOException {
        String placeholder = SeclumeSslSocketFactory.placeholder(spec);
        assertEquals(bearer(SECRET), rewritten(bearer(placeholder), "git.example.com:443"));
        // A submodule elsewhere, a redirect: the placeholder, not the secret.
        assertEquals(bearer(placeholder), rewritten(bearer(placeholder), "evil.example.org:443"));
        assertEquals(bearer(placeholder), rewritten(bearer(placeholder), "git.example.com:8443"));
        // And the first one still does.
        assertEquals(bearer(SECRET), rewritten(bearer(placeholder), "git.example.com:443"));
    }

    @Test
    void basicIsBoundTheSameWay() throws IOException {
        String placeholder = SeclumeSslSocketFactory.placeholder(spec);
        assertEquals(basic("deploy", SECRET), rewritten(basic("deploy", placeholder),
                "git.example.com:443"));
        assertEquals(basic("deploy", placeholder), rewritten(basic("deploy", placeholder),
                "submodule.example.net:443"));
    }

    @Test
    void theHostIsComparedWithoutRegardToCase() throws IOException {
        String placeholder = SeclumeSslSocketFactory.placeholder(spec);
        assertEquals(bearer(SECRET), rewritten(bearer(placeholder),
                CredentialPlaceholders.server("Git.Example.COM", 443)));
        assertEquals(bearer(SECRET), rewritten(bearer(placeholder),
                CredentialPlaceholders.server("git.example.com", 443)));
        assertEquals("[2001:db8::1]:443", CredentialPlaceholders.server("2001:DB8::1", 443));
        assertEquals("[2001:db8::1]:443", CredentialPlaceholders.server("[2001:db8::1]", 443));
    }

    @Test
    void aClusterNamesItsNodesAndOnlyThoseGetIt() throws IOException {
        String placeholder = SeclumeSslSocketFactory.placeholder(spec,
                List.of("es1.example.com:9200", "ES2.example.com:9200", "[2001:db8::7]:9200"));
        for (String node : List.of("es1.example.com:9200", "es2.example.com:9200",
                "[2001:db8::7]:9200", "es1.example.com:9200")) {
            assertEquals(bearer(SECRET), rewritten(bearer(placeholder), node), node);
        }
        assertEquals(bearer(placeholder), rewritten(bearer(placeholder), "es3.example.com:9200"));
        assertEquals(bearer(placeholder), rewritten(bearer(placeholder), "es1.example.com:9300"));
    }

    @Test
    void aServerListThatIsNotHostAndPortIsRefused() {
        for (String bad : List.of("es1.example.com", "es1.example.com:", ":9200",
                "es1.example.com:http")) {
            assertThrows(IllegalArgumentException.class,
                    () -> SeclumeSslSocketFactory.placeholder(spec, List.of(bad)), bad);
        }
    }

    @Test
    void anUnknownPlaceholderIsStillRefused() {
        String forged = CredentialPlaceholders.PREFIX + "0123456789abcdef01234567-99999";
        IOException refused = assertThrows(IOException.class,
                () -> rewritten(bearer(forged), "git.example.com:443"));
        assertTrue(refused.getMessage().contains("did not hand out"), refused.getMessage());
    }

    @Test
    void racingFirstRequestsBindOneServer() throws Exception {
        String placeholder = SeclumeSslSocketFactory.placeholder(spec);
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger withSecret = new AtomicInteger();
        List<Thread> started = new ArrayList<>();
        List<Throwable> failures = java.util.Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < threads; i++) {
            String server = "host" + i + ".example.com:443";
            started.add(Thread.ofPlatform().start(() -> {
                try {
                    start.await();
                    if (rewritten(bearer(placeholder), server).contains(SECRET)) {
                        withSecret.incrementAndGet();
                    }
                } catch (Throwable e) {
                    failures.add(e);
                }
            }));
        }
        start.countDown();
        for (Thread thread : started) {
            thread.join();
        }
        assertEquals(List.of(), failures);
        assertEquals(1, withSecret.get(), "the secret went to more than one server");
    }

    @Test
    void overHttp2TheFieldOfAnotherServerKeepsThePlaceholder() throws IOException {
        String placeholder = SeclumeSslSocketFactory.placeholder(spec);
        assertTrue(sentOverHttp2(placeholder, "api.example.com:443").contains(SECRET));
        String elsewhere = sentOverHttp2(placeholder, "other.example.com:443");
        assertTrue(!elsewhere.contains(SECRET), elsewhere);
        assertTrue(elsewhere.contains("Bearer " + placeholder), elsewhere);
    }

    private static final byte[] PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            .getBytes(StandardCharsets.US_ASCII);

    private static void literal(ByteArrayOutputStream out, String name, String value) {
        out.write(0x00);
        out.write(name.length());
        out.writeBytes(name.getBytes(StandardCharsets.US_ASCII));
        out.write(value.length());
        out.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static String sentOverHttp2(String placeholder, String server) throws IOException {
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        literal(block, ":method", "GET");
        literal(block, ":scheme", "https");
        literal(block, ":path", "/v1/things");
        literal(block, "authorization", "Bearer " + placeholder);
        byte[] fields = block.toByteArray();
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.writeBytes(PREFACE);
        wire.write(fields.length >>> 16);
        wire.write(fields.length >>> 8);
        wire.write(fields.length);
        wire.write(0x1);
        wire.write(0x5);
        wire.writeBytes(new byte[] {0, 0, 0, 1});
        wire.writeBytes(fields);
        byte[] bytes = wire.toByteArray();
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        new Http2Requests(buffer -> {
            byte[] piece = new byte[buffer.remaining()];
            buffer.get(piece);
            sent.writeBytes(piece);
        }, server).consume(bytes, 0, bytes.length);
        return sent.toString(StandardCharsets.ISO_8859_1);
    }
}
