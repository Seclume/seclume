package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.tck.FakeWorkloadApi;

/**
 * An embedded Tomcat serving mutual TLS between SPIFFE workloads: its key
 * manager and trust from a stand-in SPIRE agent ({@link FakeWorkloadApi}),
 * a client certificate demanded and checked by SPIFFE ID - and an SVID rotated
 * under the running connector, served from the next connection on.
 */
@Timeout(120)
class TomcatSpiffeTest {

    private static final String WEB = "spiffe://example.org/web";
    private static final String CLIENT = "spiffe://example.org/client";

    @TempDir
    Path directory;

    @Test
    void tomcatServesWorkloadsByTheirSpiffeIdsAndTakesUpARotatedSvid() throws Exception {
        assumeTrue(PrivateSigningKey.available(), "OpenSSL 3 on 64-bit Linux or CNG on Windows");
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "2", "-subj", "/O=example.org", "-keyout", "ca.key",
                "-out", "ca.pem");
        openssl("x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der");
        byte[] ca = Files.readAllBytes(directory.resolve("ca.der"));
        byte[][] first = svid("first", WEB);
        byte[][] second = svid("second", WEB);
        byte[][] client = svid("client", CLIENT);
        AtomicReference<byte[][]> served = new AtomicReference<>(first);

        try (FakeWorkloadApi webAgent = new FakeWorkloadApi(directory.resolve("web.sock"),
                () -> FakeWorkloadApi.x509SvidResponse(WEB, served.get()[0], served.get()[1],
                        ca));
             FakeWorkloadApi clientAgent = new FakeWorkloadApi(
                     directory.resolve("client.sock"),
                     () -> FakeWorkloadApi.x509SvidResponse(CLIENT, client[0], client[1], ca))) {
            SeclumeKeys.Spiffe web = SeclumeKeys.spiffe("socket=unix://" + webAgent.socket()
                    + "&peer-ids=" + CLIENT);
            X509ExtendedKeyManager keys =
                    (X509ExtendedKeyManager) web.keys().getKeyManagers()[0];
            X509TrustManager trust = (X509TrustManager) web.trust().getTrustManagers()[0];

            Tomcat tomcat = new Tomcat();
            tomcat.setBaseDir(directory.resolve("tomcat").toString());
            Connector connector = new Connector();
            connector.setPort(0);
            SeclumeTomcat.enableHttps(connector, keys, trust, SeclumeTomcat.ClientAuth.NEED);
            tomcat.setConnector(connector);
            Context context = tomcat.addContext("", null);
            Tomcat.addServlet(context, "who", new HttpServlet() {
                private static final long serialVersionUID = 1L;

                @Override
                protected void doGet(HttpServletRequest request, HttpServletResponse response)
                        throws IOException {
                    X509Certificate[] peer = (X509Certificate[]) request.getAttribute(
                            "jakarta.servlet.request.X509Certificate");
                    String id;
                    try {
                        id = peer == null ? "none" : SpiffeTrustManager.spiffeId(peer[0]);
                    } catch (java.security.cert.CertificateException unreadable) {
                        id = "unreadable: " + unreadable.getMessage();
                    }
                    response.getWriter().write("secure=" + request.isSecure() + " peer=" + id);
                }
            });
            context.addServletMapping("/", "who");
            tomcat.start();
            try {
                SSLContext workload = SeclumeKeys.spiffeSslContext("socket=unix://"
                        + clientAgent.socket() + "&peer-ids=" + WEB);
                AtomicReference<X509Certificate> seen = new AtomicReference<>();
                String answer = get(workload, connector.getLocalPort(), seen);
                assertTrue(answer.contains("secure=true peer=" + CLIENT), answer);
                X509Certificate before = seen.get();

                // A client with no certificate does not get in.
                KeyStore authority = KeyStore.getInstance("PKCS12");
                authority.load(null, null);
                authority.setCertificateEntry("ca",
                        SeclumeKeys.certificates(directory.resolve("ca.pem"))[0]);
                TrustManagerFactory trusting = TrustManagerFactory.getInstance("PKIX");
                trusting.init(authority);
                SSLContext anonymous = SSLContext.getInstance("TLSv1.3");
                anonymous.init(null, trusting.getTrustManagers(), null);
                assertThrows(IOException.class, () -> get(anonymous,
                        connector.getLocalPort(), new AtomicReference<>()));

                // The agent rotates; the connector, untouched, serves the new SVID.
                served.set(second);
                assertTrue(((SpiffeKeyManager) keys).renewNow(), "the new SVID was not taken");
                answer = get(workload, connector.getLocalPort(), seen);
                assertTrue(answer.contains("peer=" + CLIENT), answer);
                assertNotEquals(before.getSerialNumber(), seen.get().getSerialNumber());
                assertEquals(SeclumeKeys.certificates(directory.resolve("second.pem"))[0]
                        .getSerialNumber(), seen.get().getSerialNumber());
            } finally {
                tomcat.stop();
                tomcat.destroy();
            }
        }
    }

    /** One GET over a fresh connection; the server's certificate into {@code seen}. */
    private static String get(SSLContext context, int port, AtomicReference<X509Certificate> seen)
            throws IOException {
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(
                "localhost", port)) {
            socket.setSoTimeout(30_000);
            socket.startHandshake();
            seen.set((X509Certificate) socket.getSession().getPeerCertificates()[0]);
            OutputStream out = socket.getOutputStream();
            out.write(("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = socket.getInputStream();
            String answer = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            if (answer.isEmpty()) {
                throw new IOException("the server closed the connection without an answer");
            }
            return answer;
        }
    }

    /** An SVID's certificate and PKCS#8 key, both DER, made by the test CA. */
    private byte[][] svid(String name, String id) throws Exception {
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-subj", "/O=example.org", "-keyout", name + ".key", "-out", name + ".csr");
        Files.writeString(directory.resolve(name + ".ext"), "subjectAltName=URI:" + id
                + "\nextendedKeyUsage=clientAuth,serverAuth\nkeyUsage=digitalSignature\n");
        openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "2", "-extfile", name + ".ext", "-out",
                name + ".pem");
        openssl("x509", "-in", name + ".pem", "-outform", "DER", "-out", name + ".der");
        openssl("pkcs8", "-topk8", "-nocrypt", "-in", name + ".key", "-outform", "DER",
                "-out", name + ".p8");
        return new byte[][] {Files.readAllBytes(directory.resolve(name + ".der")),
            Files.readAllBytes(directory.resolve(name + ".p8"))};
    }

    private void openssl(String... arguments) throws IOException, InterruptedException {
        // Through /bin/sh, which finds openssl on the PATH; the arguments stay arguments.
        List<String> command = new ArrayList<>(List.of("-c", "exec openssl \"$@\"", "openssl"));
        command.addAll(List.of(arguments));
        Process process = space.seclume.tck.Shell.builder(command.toArray(String[]::new))
                .directory(directory.toFile()).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IOException("openssl " + arguments[0] + " failed: " + output);
        }
    }
}
