package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.actuate.endpoint.web.WebEndpointResponse;
import org.springframework.boot.actuate.management.HeapDumpWebEndpoint;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.io.Resource;

import space.seclume.heapdump.Discovery;

/**
 * {@code /actuator/heapdump} through seclume: a dump of this very JVM, with
 * a token in it, comes out without the token - and a dump that cannot be made
 * clean does not come out at all.
 */
@Timeout(300)
class HeapDumpEndpointTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** What the dump is to lose: a token, and its body held apart as a library would. */
    static String token;
    static String body;

    @TempDir
    Path directory;

    private static String alnum(int length) {
        String letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(letters.charAt(RANDOM.nextInt(letters.length())));
        }
        return out.toString();
    }

    @Test
    void aDumpOfThisJvmIsServedWithoutTheCredentialsItHolds() throws IOException {
        body = alnum(36);
        token = "ghp_" + body;
        WebEndpointResponse<Resource> response =
                new SeclumeHeapDumpWebEndpoint(Set.of()).heapDump(true);
        assertEquals(WebEndpointResponse.STATUS_OK, response.getStatus());
        Path served = directory.resolve("served.hprof");
        try (InputStream in = response.getBody().getInputStream()) {
            Files.copy(in, served);
        }
        assertFalse(response.getBody().getFile().exists(),
                "the served copy outlived its response");
        assertTrue(Discovery.scan(served, Set.of()).clean(),
                "the served dump still holds a credential of a known shape");
        assertFalse(contains(served, body.getBytes(StandardCharsets.US_ASCII)),
                "the token's body is in the served dump");
        assertFalse(contains(served, body.getBytes(StandardCharsets.UTF_16BE)));
        assertTrue(token.endsWith(body), "the token was held to the end");
    }

    /** A secret of no known shape that the application leaked - as it does, into a String. */
    static String leaked;

    /**
     * The application's own secret, named by {@code seclume.heapdump.secrets}:
     * a value of no known shape, which discovery cannot see. The application
     * leaked it into a String; the served dump must not have it.
     */
    @Test
    void aNamedSecretOfNoShapeIsRedactedFromTheServedDump() throws Exception {
        Path secretFile = directory.resolve("api-key");
        Process openssl = new ProcessBuilder("openssl", "rand", "-hex", "-out",
                secretFile.toString(), "20").redirectErrorStream(true).start();
        assertTrue(openssl.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)
                && openssl.exitValue() == 0);
        leaked = Files.readString(secretFile).strip();   // what the application did
        try (RedactionSecrets secrets = new RedactionSecrets(Map.of("api-key",
                space.seclume.secret.SecretProviders.of(Map.of("provider", "file",
                        "path", secretFile.toString()))))) {
            assertEquals(List.of("api-key"), secrets.labels().stream()
                    .filter("api-key"::equals).toList());
            WebEndpointResponse<Resource> response =
                    new SeclumeHeapDumpWebEndpoint(Set.of(), secrets).heapDump(true);
            assertEquals(WebEndpointResponse.STATUS_OK, response.getStatus());
            Path served = directory.resolve("served.hprof");
            try (InputStream in = response.getBody().getInputStream()) {
                Files.copy(in, served);
            }
            assertFalse(contains(served, leaked.getBytes(StandardCharsets.US_ASCII)),
                    "the named secret is in the served dump");
            assertFalse(contains(served, leaked.getBytes(StandardCharsets.UTF_16BE)));
        }
        assertTrue(leaked.length() == 40);
    }

    @Test
    void aDumpThatCannotBeMadeCleanIsNotServedAndIsDeleted() throws IOException {
        // A credential in a file that is no HPROF: found, but the String
        // hashes cannot be cleared - so nothing goes out.
        byte[] random = new byte[24];
        RANDOM.nextBytes(random);
        String vault = "hvs." + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(random);
        Path raw = Files.writeString(directory.resolve("heap-raw.hprof"),
                "\u0001 " + vault + " \u0002");
        WebEndpointResponse<Resource> response = new SeclumeHeapDumpWebEndpoint(Set.of(),
                () -> raw.toFile()).heapDump(true);
        assertEquals(WebEndpointResponse.STATUS_INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(Files.exists(raw), "the dump itself was left behind");
        try (Stream<Path> left = Files.list(directory)) {
            assertEquals(0, left.count(), "a copy was left behind");
        }
    }

    @Test
    void theDumpItselfIsDeletedOnceTheCopyIsMade() throws IOException {
        Path raw = Files.writeString(directory.resolve("heap-raw.hprof"),
                "\u0001 nothing like a credential \u0002");
        WebEndpointResponse<Resource> response = new SeclumeHeapDumpWebEndpoint(Set.of(),
                () -> raw.toFile()).heapDump(null);
        assertEquals(WebEndpointResponse.STATUS_OK, response.getStatus());
        assertFalse(Files.exists(raw), "the dump itself was left behind");
        try (InputStream in = response.getBody().getInputStream()) {
            assertEquals("\u0001 nothing like a credential \u0002",
                    new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        try (Stream<Path> left = Files.list(directory)) {
            assertEquals(0, left.count(), "the served copy outlived its response");
        }
    }

    @Test
    void anUnknownDetectorIsATypoNotAFilter() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> new SeclumeHeapDumpWebEndpoint(Set.of("jwts")));
        assertTrue(refused.getMessage().contains("jwts"), refused.getMessage());
    }

    private static AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeHeapDumpAutoConfiguration.class);
        context.refresh();
        return context;
    }

    @Test
    void theEndpointTakesBootsPlaceUnlessToldNotTo() {
        try (AnnotationConfigApplicationContext context = context(Map.of())) {
            assertTrue(context.getBean(HeapDumpWebEndpoint.class)
                    instanceof SeclumeHeapDumpWebEndpoint);
        }
        Map<String, Object> off = new LinkedHashMap<>();
        off.put("seclume.heapdump.redact", "false");
        try (AnnotationConfigApplicationContext context = context(off)) {
            assertEquals(0, context.getBeansOfType(HeapDumpWebEndpoint.class).size());
        }
        Map<String, Object> ignore = new LinkedHashMap<>();
        ignore.put("seclume.heapdump.ignore", "jwt,url-password");
        try (AnnotationConfigApplicationContext context = context(ignore)) {
            assertTrue(context.getBean(HeapDumpWebEndpoint.class)
                    instanceof SeclumeHeapDumpWebEndpoint);
        }
        Map<String, Object> typo = new LinkedHashMap<>();
        typo.put("seclume.heapdump.ignore", "jwt,url-pasword");
        BeanCreationException refused = assertThrows(BeanCreationException.class,
                () -> context(typo).close());
        assertTrue(String.valueOf(refused.getMostSpecificCause().getMessage())
                .contains("url-pasword"), refused.toString());
    }

    /** Searched in windows that overlap by the pattern's length, so a dump of any size fits. */
    private static boolean contains(Path file, byte[] pattern) throws IOException {
        byte[] window = new byte[(8 << 20) + pattern.length];
        try (InputStream in = Files.newInputStream(file)) {
            int kept = 0;
            while (true) {
                int n = in.readNBytes(window, kept, window.length - kept);
                int length = kept + n;
                outer:
                for (int i = 0; i + pattern.length <= length; i++) {
                    for (int j = 0; j < pattern.length; j++) {
                        if (window[i + j] != pattern[j]) {
                            continue outer;
                        }
                    }
                    return true;
                }
                if (n == 0 || length < window.length) {
                    return false;
                }
                kept = pattern.length - 1;
                System.arraycopy(window, length - kept, window, 0, kept);
            }
        }
    }
}
