package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.internal.TrustChoice;

/**
 * seclume's own TLS client against other people's TLS servers - OpenSSL,
 * GnuTLS, Go's crypto/tls, rustls, the JDK's JSSE - each in the versions,
 * groups and keys it offers, and against servers that must be refused.
 *
 * <p>A client tested only against itself proves that it agrees with itself.
 * Every server here was written by somebody else, from the same RFCs, and
 * each handshake that completes - with the chain and the host name checked
 * against a CA, not pinned and not skipped - is one more independent reading
 * of the specification that agrees with this one. Each that must fail is a
 * check that it fails for the right reason: an expired certificate, a wrong
 * name, a stranger's CA, a protocol or a key exchange this client does not
 * speak on purpose.
 *
 * <p>The servers are started outside, by {@code tls-interop/run.sh} and the
 * {@code tls-interop} workflow; this reads what they are from a file:
 *
 * <pre>
 * # name          port  expect   reason the refusal must name (refusals only)
 * openssl-1.3-p256 9001 ok
 * gnutls-1.2-rsa   9105 ok
 * expired          9201 refused  expired
 * </pre>
 *
 * {@code SECLUME_TLS_INTEROP} names that file, {@code SECLUME_TLS_INTEROP_CA}
 * the CA every server's certificate is issued by. Without them the test is
 * skipped; the workflow makes a skip a failure.
 */
@Timeout(300)
class TlsInteropTest {

    private static final String CASES = System.getenv("SECLUME_TLS_INTEROP");
    private static final String CA = System.getenv("SECLUME_TLS_INTEROP_CA");

    /** One server and what has to happen there. */
    record Case(String name, int port, boolean expectOk, String reason) {
        @Override
        public String toString() {
            return name;
        }
    }

    static Stream<Case> cases() throws IOException {
        if (CASES == null || CA == null) {
            return Stream.of(new Case("not configured", 0, true, ""));
        }
        List<Case> cases = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(CASES))) {
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String[] field = trimmed.split("\\s+", 4);
            cases.add(new Case(field[0], Integer.parseInt(field[1]), field[2].equals("ok"),
                    field.length > 3 ? field[3] : ""));
        }
        return cases.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void eachServerIsMetAsItMustBe(Case server) throws Exception {
        Assumptions.assumeTrue(CASES != null && CA != null,
                "SECLUME_TLS_INTEROP and SECLUME_TLS_INTEROP_CA are not set");
        if (server.expectOk()) {
            String description = fetch(server.port());
            assertTrue(description.startsWith("TLS"), server.name() + ": " + description);
            System.out.println(server.name() + ": " + description);
        } else {
            try {
                String description = fetch(server.port());
                fail(server.name() + " must be refused, and was accepted: " + description);
            } catch (Exception refused) {
                String message = chain(refused).toLowerCase(Locale.ROOT);
                assertTrue(message.contains(server.reason().toLowerCase(Locale.ROOT)),
                        server.name() + " was refused, but not because of '" + server.reason()
                                + "': " + message);
                System.out.println(server.name() + ": refused - " + message);
            }
        }
    }

    /** A verified handshake, then one HTTP request; the description of what was negotiated. */
    private static String fetch(int port) throws Exception {
        TrustChoice.Choice trust = TrustChoice.of("x?" + TrustChoice.ROOT_CERT + "=" + CA,
                new Properties());
        TlsLayer tls = TrustChoice.using(trust, () -> {
            try {
                return TlsLayers.start(TlsStack.SECLUME,
                        SocketTransport.connect("localhost", port, 5000), "localhost", port, true);
            } catch (IOException e) {
                throw new SQLException(e.getMessage(), "08001", e);
            }
        });
        try (tls) {
            tls.write(ByteBuffer.wrap("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII)));
            ByteBuffer in = ByteBuffer.allocate(1 << 12);
            int read = tls.read(in);
            assertTrue(read > 0, "the server sent nothing over the connection");
            return tls.description();
        }
    }

    /** Every message down the cause chain - the reason may sit at any depth. */
    private static String chain(Throwable failure) {
        StringBuilder text = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            text.append(t.getClass().getSimpleName()).append(": ").append(t.getMessage())
                    .append(" | ");
        }
        return text.toString();
    }
}
