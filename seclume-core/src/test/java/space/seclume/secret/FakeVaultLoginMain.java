package space.seclume.secret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLContext;

import space.seclume.tls.TestCertificates;

/**
 * Vault for {@link VaultLoginHeapTest}, in a JVM of its own.
 *
 * <p>It makes up a JWT, a client token and a database password, writes each
 * into a file in the directory it is given - the test searches its own heap
 * for them - and answers like Vault: a JWT login only with exactly that JWT
 * and the role {@code app}, everything else only with exactly that token.
 * A wrong byte anywhere is a 403, so a test that gets through has sent what
 * it should.
 *
 * <p>Prints {@code READY <port>}; when its standard input closes, prints what
 * it served and ends.
 */
public final class FakeVaultLoginMain {

    private FakeVaultLoginMain() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        SecureRandom random = new SecureRandom();
        String jwt = base64url(random, 36) + "." + base64url(random, 120) + "."
                + base64url(random, 256);
        String clientToken = "hvs." + base64url(random, 72);
        String password = "A1a-" + base64url(random, 24);
        Files.writeString(directory.resolve("jwt.txt"), jwt + "\n");
        Files.writeString(directory.resolve("client-token.txt"), clientToken);
        Files.writeString(directory.resolve("password.txt"), password);

        AtomicInteger logins = new AtomicInteger();
        AtomicInteger renewals = new AtomicInteger();
        AtomicInteger fetches = new AtomicInteger();
        AtomicInteger leaseRevocations = new AtomicInteger();
        AtomicInteger tokenRevocations = new AtomicInteger();
        String tokenAnswer = "{\"auth\":{\"client_token\":\"" + clientToken
                + "\",\"lease_duration\":3600,\"renewable\":true}}";

        FakeVaultServer.Handler handler = request -> {
            if (request.is("POST", "/v1/auth/jwt/login")) {
                if (!request.body().equals("{\"role\":\"app\",\"jwt\":\"" + jwt + "\"}")) {
                    return new FakeVaultServer.Answer(403, "{\"errors\":[\"denied\"]}");
                }
                logins.incrementAndGet();
                return new FakeVaultServer.Answer(200, tokenAnswer);
            }
            if (!clientToken.equals(request.header("X-Vault-Token"))) {
                return new FakeVaultServer.Answer(403, "{\"errors\":[\"permission denied\"]}");
            }
            if (request.is("GET", "/v1/database/creds/app")) {
                fetches.incrementAndGet();
                return new FakeVaultServer.Answer(200, "{\"lease_id\":\"database/creds/app/1\","
                        + "\"renewable\":true,\"lease_duration\":3600,"
                        + "\"data\":{\"username\":\"v-app-1\",\"password\":\"" + password + "\"}}");
            }
            if (request.is("POST", "/v1/auth/token/renew-self")) {
                renewals.incrementAndGet();
                return new FakeVaultServer.Answer(200, tokenAnswer);
            }
            if (request.is("PUT", "/v1/sys/leases/revoke")) {
                leaseRevocations.incrementAndGet();
                return new FakeVaultServer.Answer(204, "");
            }
            if (request.is("POST", "/v1/auth/token/revoke-self")) {
                tokenRevocations.incrementAndGet();
                return new FakeVaultServer.Answer(204, "");
            }
            return new FakeVaultServer.Answer(404, "{\"errors\":[]}");
        };

        try (TestCertificates certificates = TestCertificates.generate()) {
            SSLContext context = FakeVaultServer.context(certificates);
            try (FakeVaultServer vault = new FakeVaultServer(context, handler)) {
                System.out.println("READY " + vault.port());
                System.out.flush();
                while (System.in.read() >= 0) {
                    // until the test closes the pipe
                }
                System.out.println("DONE logins=" + logins + " renewals=" + renewals
                        + " fetches=" + fetches + " lease-revocations=" + leaseRevocations
                        + " token-revocations=" + tokenRevocations);
            }
        } catch (IOException e) {
            System.out.println("FAILED " + e);
        }
    }

    private static String base64url(SecureRandom random, int bytes) {
        byte[] raw = new byte[bytes];
        random.nextBytes(raw);
        return new String(Base64.getUrlEncoder().withoutPadding().encode(raw),
                StandardCharsets.US_ASCII);
    }
}
