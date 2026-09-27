package space.seclume.gcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.OutputStream;
import java.lang.ref.Reference;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.google.auth.oauth2.ServiceAccountCredentials;
import com.sun.net.httpserver.HttpServer;

import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.tck.NoSecretInHeap;

/**
 * A service account key file, and a token endpoint that checks each JWT the
 * Google auth library sends against the account's public key.
 */
class ServiceAccountTest {

    @TempDir
    static Path directory;

    static HttpServer tokens;
    static PublicKey publicKey;
    static final List<String> problems = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void start() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        tokens = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        tokens.createContext("/token", exchange -> {
            String form = new String(exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8);
            String assertion = "";
            for (String pair : form.split("&")) {
                if (pair.startsWith("assertion=")) {
                    assertion = URLDecoder.decode(pair.substring(10), StandardCharsets.UTF_8);
                }
            }
            String[] parts = assertion.split("\\.");
            boolean valid;
            try {
                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(publicKey);
                verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
                valid = verifier.verify(Base64.getUrlDecoder().decode(parts[2]));
                String claims = new String(Base64.getUrlDecoder().decode(parts[1]),
                        StandardCharsets.UTF_8);
                valid &= claims.contains("\"iss\":\"app@project.iam.gserviceaccount.com\"");
            } catch (Exception e) {
                valid = false;
            }
            if (!valid) {
                problems.add("an assertion that does not verify");
            }
            byte[] body = (valid ? "{\"access_token\":\"ya29.issued\",\"expires_in\":3600,"
                    + "\"token_type\":\"Bearer\"}" : "{\"error\":\"invalid_grant\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(valid ? 200 : 400, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        tokens.start();
        String tokenUri = "http://127.0.0.1:" + tokens.getAddress().getPort() + "/token";
        Path script = directory.resolve("key.sh");
        Files.writeString(script, String.join("\n",
                "set -e", "cd '" + directory + "'",
                "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem 2>/dev/null",
                "openssl pkey -in key.pem -pubout -outform DER -out public.der",
                "openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out key.der",
                "openssl pkey -in key.pem -text -noout | sed -n '/^prime1:/,/^[a-zA-Z]/p'"
                        + " | sed '1d;$d' | tr -d ' :\\n' | sed 's/^00//'"
                        + " | perl -ne 'print pack(\"H*\", $_)' > secret.bin",
                "{ printf '{\"type\":\"service_account\",\"project_id\":\"project\","
                        + "\"private_key_id\":\"k1\",\"private_key\":\"'",
                "  awk '{printf \"%s\\\\n\", $0}' key.pem",
                "  printf '\",\"client_email\":\"app@project.iam.gserviceaccount.com\","
                        + "\"client_id\":\"1\",\"token_uri\":\"" + tokenUri + "\"}'",
                "} > service-account.json", ""));
        Process process = new ProcessBuilder("/bin/sh", script.toString())
                .redirectErrorStream(true).start();
        assertEquals(0, process.waitFor(), new String(process.getInputStream().readAllBytes()));
        publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(Files.readAllBytes(directory.resolve("public.der"))));
    }

    @AfterAll
    static void stop() {
        if (tokens != null) {
            tokens.stop(0);
        }
    }

    private static String spec() {
        return "provider=file&path=" + directory.resolve("service-account.json")
                + "&scopes=https://www.googleapis.com/auth/cloud-platform";
    }

    @Test
    void anAccessTokenForASignedAssertion() throws Exception {
        ServiceAccountCredentials credentials = SeclumeGcp.credentials(spec());
        assertEquals("app@project.iam.gserviceaccount.com", credentials.getClientEmail());
        assertEquals("project", credentials.getProjectId());
        assertEquals("ya29.issued", credentials.refreshAccessToken().getTokenValue());
        assertEquals(List.of(), problems);
        assertEquals("RSA", credentials.getPrivateKey().getAlgorithm());
        assertEquals(null, credentials.getPrivateKey().getEncoded());
    }

    @Test
    void notAServiceAccountFile() throws Exception {
        Path other = directory.resolve("user.json");
        Files.writeString(other, "{\"type\":\"authorized_user\"}");
        assertThrows(IllegalArgumentException.class, () -> SeclumeGcp.credentials(
                "provider=file&path=" + other));
    }

    @Test
    void theKeyIsNotOnTheHeap() throws Exception {
        for (int i = 0; i < 2; i++) {
            SeclumeGcp.credentials(spec()).refreshAccessToken();
        }
        NoSecretInHeap.assertAbsent(directory.resolve("key.der"));
        NoSecretInHeap.assertAbsent(directory.resolve("secret.bin"));
        PrivateKey usual = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve("key.der"))));
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("secret.bin")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(usual);
    }
}
