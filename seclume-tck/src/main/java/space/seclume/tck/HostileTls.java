package space.seclume.tck;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * The ways a server - or whoever sits in front of it - makes TLS fail after
 * it has said yes to it, for the tests that hold a driver to never falling
 * back to less than it was asked for.
 *
 * <p>Each protocol says yes its own way - PostgreSQL an {@code S} after the
 * SSLRequest, MySQL a capability bit and the client's SSL request, TDS a
 * PRELOGIN answer - so the test does that part; then {@link #misbehave}
 * takes the socket over. What it does:
 *
 * <ul>
 * <li>{@link Behaviour#NOT_TLS}: bytes that are not TLS;</li>
 * <li>{@link Behaviour#HANGS_UP}: reads the ClientHello's record header and closes;</li>
 * <li>{@link Behaviour#FATAL_ALERT}: a fatal handshake_failure alert;</li>
 * <li>{@link Behaviour#SELF_SIGNED}: a finished handshake with a self-signed
 *     certificate no trust store has;</li>
 * <li>{@link Behaviour#OTHER_HOST}: one from {@link #caPem()} - a CA the
 *     test trusts - for {@code other.example} and {@code 127.0.0.2};</li>
 * <li>{@link Behaviour#EXPIRED}: one from that CA for {@code 127.0.0.1} that
 *     expired eight days ago.</li>
 * </ul>
 *
 * <p>The last three finish the handshake if the client lets them, and then
 * report what arrived inside TLS - the login, which must not arrive when the
 * client was asked to check the certificate.
 *
 * <p>The certificates are made by {@code keytool} in a directory the test
 * owns; nothing here is a fixture from anywhere else.
 */
public final class HostileTls {

    private static final String PASSWORD = "hostile-tls";

    /** What the server does once it has said yes to TLS. */
    public enum Behaviour {
        NOT_TLS, HANGS_UP, FATAL_ALERT, SELF_SIGNED, OTHER_HOST, EXPIRED;

        /** Whether it completes a handshake when the client accepts its certificate. */
        public boolean handshakes() {
            return ordinal() >= SELF_SIGNED.ordinal();
        }

        /** Whether its certificate is from {@link #caPem()}, which the client must then trust. */
        public boolean fromTrustedCa() {
            return this == OTHER_HOST || this == EXPIRED;
        }
    }

    private final Path directory;
    private final Path caPem;
    private final SSLContext selfSigned;
    private final SSLContext otherHost;
    private final SSLContext expired;

    private HostileTls(Path directory) throws Exception {
        this.directory = directory;
        Path ca = directory.resolve("ca.p12");
        keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=hostile-ca", "-ext", "bc:c", "-validity", "10", "-keystore", ca);
        caPem = directory.resolve("ca.pem");
        keytool("-exportcert", "-rfc", "-alias", "ca", "-keystore", ca, "-file", caPem);
        otherHost = issued(ca, "other", "san=dns:other.example,ip:127.0.0.2", "-validity", "5");
        expired = issued(ca, "expired", "san=ip:127.0.0.1", "-startdate", "-10d", "-validity", "2");
        Path own = directory.resolve("self.p12");
        keytool("-genkeypair", "-alias", "self", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=hostile-self", "-ext", "san=ip:127.0.0.1", "-validity", "5",
                "-keystore", own);
        selfSigned = context(own);
    }

    /** The CA, its certificates and their keys, made in {@code directory}. */
    public static HostileTls create(Path directory) throws Exception {
        return new HostileTls(directory);
    }

    /** The CA that issued {@link Behaviour#OTHER_HOST}'s and {@link Behaviour#EXPIRED}'s certificate, as PEM. */
    public Path caPem() {
        return caPem;
    }

    /**
     * Plays {@code behaviour} on a socket whose server has just said yes to
     * TLS. Returns the first bytes the client sent inside a finished
     * handshake, or null when there was none - the client refused the
     * certificate, or the behaviour has no handshake.
     */
    public byte[] misbehave(Behaviour behaviour, Socket plain) throws IOException {
        InputStream in = plain.getInputStream();
        OutputStream out = plain.getOutputStream();
        switch (behaviour) {
            case NOT_TLS -> {
                // seclume-allow: a fixed text that is not TLS, no secret
                out.write("HTTP/1.1 400 Bad Request\r\n\r\nthis is not TLS at all".getBytes(StandardCharsets.US_ASCII));
                out.flush();
                drain(in);
                return null;
            }
            case HANGS_UP -> {
                in.readNBytes(5);
                return null;
            }
            case FATAL_ALERT -> {
                in.readNBytes(5);
                // alert, TLS 1.2 record version, length 2: fatal, handshake_failure
                out.write(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28});
                out.flush();
                drain(in);
                return null;
            }
            default -> {
                SSLContext context = switch (behaviour) {
                    case SELF_SIGNED -> selfSigned;
                    case OTHER_HOST -> otherHost;
                    default -> expired;
                };
                SSLSocket tls = (SSLSocket) context.getSocketFactory()
                        .createSocket(plain, "127.0.0.1", plain.getPort(), true);
                tls.setUseClientMode(false);
                try {
                    tls.startHandshake();
                    byte[] first = new byte[4096];
                    int n = tls.getInputStream().read(first);
                    return n <= 0 ? null : java.util.Arrays.copyOf(first, n);
                } catch (IOException refusedByTheClient) {
                    return null;
                }
            }
        }
    }

    /** What arrives until the client hangs up or the socket's timeout passes. */
    public static byte[] readSome(InputStream in) {
        ByteArrayOutputStream read = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        try {
            for (int n; (n = in.read(buffer)) > 0; ) {
                read.write(buffer, 0, n);
            }
        } catch (SocketTimeoutException quiet) {
            // what came, came
        } catch (IOException reset) {
            // the client is gone
        }
        return read.toByteArray();
    }

    private static void drain(InputStream in) {
        readSome(in);
    }

    /** Whether {@code needle}, as ASCII, is somewhere in {@code haystack}. */
    public static boolean contains(byte[] haystack, String needle) {
        if (haystack == null) {
            return false;
        }
        byte[] wanted = needle.getBytes(StandardCharsets.US_ASCII); // seclume-allow: what a test looks for, no secret
        outer:
        for (int i = 0; i + wanted.length <= haystack.length; i++) {
            for (int j = 0; j < wanted.length; j++) {
                if (haystack[i + j] != wanted[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private SSLContext issued(Path ca, String alias, String san, String... validity)
            throws Exception {
        Path store = directory.resolve(alias + ".p12");
        keytool("-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=" + alias, "-validity", "5", "-keystore", store);
        Path request = directory.resolve(alias + ".csr");
        Path signed = directory.resolve(alias + ".pem");
        keytool("-certreq", "-alias", alias, "-keystore", store, "-file", request);
        List<Object> sign = new ArrayList<>(List.of("-gencert", "-alias", "ca", "-keystore", ca,
                "-infile", request, "-outfile", signed, "-rfc", "-ext", san));
        sign.addAll(List.of((Object[]) validity));
        keytool(sign.toArray());
        keytool("-importcert", "-noprompt", "-alias", "ca", "-keystore", store, "-file", caPem);
        keytool("-importcert", "-noprompt", "-alias", alias, "-keystore", store, "-file", signed);
        return context(store);
    }

    private static void keytool(Object... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        for (Object argument : arguments) {
            command.add(argument.toString());
        }
        command.addAll(List.of("-storetype", "PKCS12", "-storepass", PASSWORD));
        if (command.contains("-genkeypair")) {
            command.addAll(List.of("-keypass", PASSWORD));
        }
        Process keytool = new ProcessBuilder(command).redirectErrorStream(true).start();
        // seclume-allow: keytool's messages, for the failure below; no secret
        String output = new String(keytool.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!keytool.waitFor(60, TimeUnit.SECONDS) || keytool.exitValue() != 0) {
            throw new IllegalStateException("keytool " + command + " failed: " + output);
        }
    }

    private static SSLContext context(Path store) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }
}
