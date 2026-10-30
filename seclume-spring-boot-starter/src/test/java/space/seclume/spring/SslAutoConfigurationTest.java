package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.catalina.connector.Connector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.boot.tomcat.TomcatConnectorCustomizer;

import space.seclume.crypto.OpenSslSigningKey;

class SslAutoConfigurationTest {

    @TempDir
    static Path directory;

    static Path certificate;
    static Path key;

    @BeforeAll
    static void keys() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        Path script = directory.resolve("make-key.sh");
        java.nio.file.Files.writeString(script, "cd '" + directory + "' && "
                + "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem"
                + " && openssl req -x509 -new -key key.pem -out cert.pem -days 2"
                + " -subj /CN=localhost -addext subjectAltName=DNS:localhost\n");
        Process process = space.seclume.tck.Shell.builder(script.toString())
                .redirectErrorStream(true).start();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0);
        certificate = directory.resolve("cert.pem");
        key = directory.resolve("key.pem");
    }

    private static AnnotationConfigApplicationContext context(String... more) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("seclume.ssl.bundles.web.certificate", certificate.toString());
        properties.put("seclume.ssl.bundles.web.key", "provider=file&path=" + key);
        for (String pair : more) {
            properties.put(pair.substring(0, pair.indexOf('=')),
                    pair.substring(pair.indexOf('=') + 1));
        }
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SslAutoConfiguration.class, SeclumeSslAutoConfiguration.class);
        context.refresh();
        return context;
    }

    @Test
    void aBundleServesTls() throws Exception {
        try (AnnotationConfigApplicationContext context = context()) {
            serveOnce(context);
        }
    }

    /** With reload-interval the key manager is the reloading one - and serves the same. */
    @Test
    void aReloadingBundleServesTls() throws Exception {
        try (AnnotationConfigApplicationContext context =
                     context("seclume.ssl.bundles.web.reload-interval=1m")) {
            serveOnce(context);
        }
    }

    private static void serveOnce(AnnotationConfigApplicationContext context) throws Exception {
        {
            SslBundle bundle = context.getBean(SslBundles.class).getBundle("web");
            SSLContext server = bundle.createSslContext();
            try (SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                    .createServerSocket(0)) {
                CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                    try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                        accepted.getOutputStream().write(accepted.getInputStream().read());
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
                java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
                store.load(null, null);
                try (var in = java.nio.file.Files.newInputStream(certificate)) {
                    store.setCertificateEntry("server", java.security.cert.CertificateFactory
                            .getInstance("X.509").generateCertificate(in));
                }
                TrustManagerFactory trust = TrustManagerFactory.getInstance("PKIX");
                trust.init(store);
                SSLContext client = SSLContext.getInstance("TLS");
                client.init(null, trust.getTrustManagers(), null);
                try (SSLSocket socket = (SSLSocket) client.getSocketFactory()
                        .createSocket("localhost", listener.getLocalPort())) {
                    socket.getOutputStream().write(42);
                    assertEquals(42, socket.getInputStream().read());
                    assertEquals("TLSv1.3", socket.getSession().getProtocol());
                }
                served.get(10, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    void tomcatGetsHttpsWhenAsked() {
        try (AnnotationConfigApplicationContext context = context()) {
            assertTrue(context.getBeansOfType(TomcatConnectorCustomizer.class).isEmpty());
        }
        try (AnnotationConfigApplicationContext context =
                     context("seclume.server.ssl.bundle=web")) {
            Connector connector = new Connector();
            context.getBean(TomcatConnectorCustomizer.class).customize(connector);
            assertEquals("https", connector.getScheme());
            assertTrue(connector.getSecure());
        }
        assertThrows(Exception.class, () -> context("seclume.server.ssl.bundle=missing").close());
    }

    /**
     * {@code vault-pki=} instead of the files: wired to Vault - here one that is
     * not there, so the start fails saying so - and never beside them.
     */
    @Test
    void aBundleFromVaultsPki() throws Exception {
        Path token = java.nio.file.Files.writeString(directory.resolve("vault-token"), "t");
        String vault = "seclume.ssl.bundles.client.vault-pki=address=https://127.0.0.1:1"
                + "&pki-role=client&common-name=orders.svc&timeout-millis=2000"
                + "&token-provider=file&token-path=" + token;
        Exception unreachable = assertThrows(Exception.class, () -> context(vault).close());
        assertTrue(rootMessage(unreachable).contains("no certificate from Vault"),
                rootMessage(unreachable));
        Exception both = assertThrows(Exception.class, () -> context(vault,
                "seclume.ssl.bundles.client.certificate=" + certificate).close());
        assertTrue(rootMessage(both).contains("vault-pki= and certificate="), rootMessage(both));
    }

    /**
     * {@code spiffe=}: the workload's X.509-SVID from the Workload API - a
     * stand-in for a SPIRE agent here - as the key, the trust domain's bundle as
     * the trust. Two contexts from the one bundle shake hands with each other,
     * mutually, the peer named by its SPIFFE ID; the SVID is listed under the
     * bundle's name; never beside files; and served by Tomcat, which can demand
     * a client certificate of the trust domain.
     */
    @Test
    @SuppressWarnings("unchecked")
    void aBundleFromTheSpiffeWorkloadApi() throws Exception {
        Path script = directory.resolve("make-svid.sh");
        java.nio.file.Files.writeString(script, "cd '" + directory + "' && "
                + "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
                + " -days 2 -subj /O=example.org -keyout ca.key -out ca.pem"
                + " && openssl x509 -in ca.pem -outform DER -out ca.der"
                + " && openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
                + " -subj /O=example.org -keyout svid.key -out svid.csr"
                + " && printf 'subjectAltName=URI:" + MESH + "\\nextendedKeyUsage=clientAuth,"
                + "serverAuth\\nkeyUsage=digitalSignature\\n' > svid.ext"
                + " && openssl x509 -req -in svid.csr -CA ca.pem -CAkey ca.key -CAcreateserial"
                + " -days 2 -extfile svid.ext -outform DER -out svid.der"
                + " && openssl pkcs8 -topk8 -nocrypt -in svid.key -outform DER -out svid.pk8\n");
        Process process = space.seclume.tck.Shell.builder(script.toString())
                .redirectErrorStream(true).start();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0);
        byte[] answer = space.seclume.tck.FakeWorkloadApi.x509SvidResponse(MESH,
                java.nio.file.Files.readAllBytes(directory.resolve("svid.der")),
                java.nio.file.Files.readAllBytes(directory.resolve("svid.pk8")),
                java.nio.file.Files.readAllBytes(directory.resolve("ca.der")));
        String spiffe = "seclume.ssl.bundles.mesh.spiffe=socket=unix://"
                + directory.resolve("agent.sock") + "&peer-ids=" + MESH;
        try (space.seclume.tck.FakeWorkloadApi agent = new space.seclume.tck.FakeWorkloadApi(
                directory.resolve("agent.sock"), () -> answer);
             AnnotationConfigApplicationContext context = context(spiffe)) {
            SslBundle bundle = context.getBean(SslBundles.class).getBundle("mesh");
            assertEquals(MESH, mutual(bundle.createSslContext(), bundle.createSslContext()));
            assertEquals(1, agent.calls(), "one SVID for the bundle's key and trust");

            List<Map<String, Object>> certificates = (List<Map<String, Object>>)
                    new SeclumeEndpoint(List.of()).report().get("certificates");
            Map<String, Object> shown = certificates.stream()
                    .filter(c -> c.get("name").equals("mesh"))
                    .findFirst().orElseThrow(() -> new AssertionError(certificates.toString()));
            assertEquals("spiffe", shown.get("kind"));

            Exception both = assertThrows(Exception.class, () -> context(spiffe,
                    "seclume.ssl.bundles.mesh.certificate=" + certificate).close());
            assertTrue(rootMessage(both).contains("has spiffe= and"), rootMessage(both));
            // Tomcat serves the bundle - its key manager, not one of its own - and,
            // asked to, demands a client certificate the trust domain vouches for.
            int before = agent.calls();
            try (AnnotationConfigApplicationContext served = context(spiffe,
                    "seclume.server.ssl.bundle=mesh", "seclume.server.ssl.client-auth=need")) {
                Connector connector = new Connector();
                served.getBean(TomcatConnectorCustomizer.class).customize(connector);
                assertEquals("https", connector.getScheme());
                assertTrue(connector.getSecure());
                org.apache.tomcat.util.net.SSLHostConfig[] hosts =
                        ((org.apache.coyote.http11.AbstractHttp11Protocol<?>) connector
                                .getProtocolHandler()).findSslHostConfigs();
                assertEquals(org.apache.tomcat.util.net.SSLHostConfig.CertificateVerification
                        .REQUIRED, hosts[0].getCertificateVerification());
                assertEquals(before + 1, agent.calls(), "Tomcat fetched an SVID of its own");
            }
            Exception unclear = assertThrows(Exception.class, () -> context(spiffe,
                    "seclume.server.ssl.bundle=mesh", "seclume.server.ssl.client-auth=maybe")
                    .close());
            assertTrue(rootMessage(unclear).contains("none, want or need"),
                    rootMessage(unclear));
        }
    }

    private static final String MESH = "spiffe://example.org/mesh";

    /** One mutual TLS connection between two contexts; the SPIFFE ID the server saw. */
    private static String mutual(SSLContext server, SSLContext client) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            listener.setNeedClientAuth(true);
            CompletableFuture<String> peer = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.startHandshake();
                    java.security.cert.X509Certificate seen = (java.security.cert.X509Certificate)
                            accepted.getSession().getPeerCertificates()[0];
                    accepted.getOutputStream().write(1);
                    accepted.getOutputStream().flush();
                    for (List<?> name : seen.getSubjectAlternativeNames()) {
                        if (Integer.valueOf(6).equals(name.get(0))) {
                            return String.valueOf(name.get(1));
                        }
                    }
                    return "(no URI)";
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            try (SSLSocket socket = (SSLSocket) client.getSocketFactory().createSocket(
                    java.net.InetAddress.getLoopbackAddress(), listener.getLocalPort())) {
                socket.startHandshake();
                assertEquals(1, socket.getInputStream().read());
            }
            return peer.get(30, TimeUnit.SECONDS);
        }
    }

    private static String rootMessage(Throwable thrown) {
        StringBuilder messages = new StringBuilder();
        for (Throwable t = thrown; t != null; t = t.getCause()) {
            messages.append(t.getMessage()).append(" | ");
        }
        return messages.toString();
    }

    /**
     * A bundle that keeps its certificate current is in {@code /actuator/seclume}
     * with its validity and a grade - the test certificate lives two days, so
     * critical - and in the meters, which read it each time.
     */
    @Test
    @SuppressWarnings("unchecked")
    void aReloadingBundleIsInTheEndpointAndTheMeters() throws Exception {
        try (AnnotationConfigApplicationContext context =
                     context("seclume.ssl.bundles.web.reload-interval=1m")) {
            context.getBean(SslBundles.class).getBundle("web");
            List<Map<String, Object>> certificates = (List<Map<String, Object>>)
                    new SeclumeEndpoint(List.of()).report().get("certificates");
            Map<String, Object> shown = certificates.stream()
                    .filter(c -> c.get("name").equals(certificate.toString()))
                    .findFirst().orElseThrow(() -> new AssertionError(certificates.toString()));
            assertEquals("file", shown.get("kind"));
            assertTrue(String.valueOf(shown.get("subject")).contains("CN=localhost"));
            assertEquals("critical", ((Map<String, Object>) shown.get("assessment")).get("grade"),
                    shown.toString());

            io.micrometer.core.instrument.simple.SimpleMeterRegistry registry =
                    new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
            context.getBean(SeclumeCertificateMetrics.class).bindTo(registry);
            double expiry = registry.get("seclume.certificate.expiry").tag("bundle", "web")
                    .gauge().value();
            assertTrue(expiry > 0 && expiry <= 2 * 86400, "expiry " + expiry);
            assertEquals(0.0, registry.get("seclume.certificate.renewal.failing")
                    .tag("bundle", "web").gauge().value());
        }
    }

    /**
     * The same two numbers through OpenTelemetry, with
     * {@code seclume.metrics.opentelemetry=true} and the application's
     * {@code OpenTelemetry} bean - read at each collection, attributed by bundle.
     */
    @Test
    void aReloadingBundleIsInTheOpenTelemetryGauges() throws Exception {
        io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader reader =
                io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader.create();
        try (io.opentelemetry.sdk.OpenTelemetrySdk sdk = io.opentelemetry.sdk.OpenTelemetrySdk
                .builder().setMeterProvider(io.opentelemetry.sdk.metrics.SdkMeterProvider.builder()
                        .registerMetricReader(reader).build()).build()) {
            Map<String, Object> properties = new HashMap<>();
            properties.put("seclume.ssl.bundles.web.certificate", certificate.toString());
            properties.put("seclume.ssl.bundles.web.key", "provider=file&path=" + key);
            properties.put("seclume.ssl.bundles.web.reload-interval", "1m");
            properties.put("seclume.metrics.opentelemetry", "true");
            try (AnnotationConfigApplicationContext context =
                         new AnnotationConfigApplicationContext()) {
                context.getEnvironment().getPropertySources()
                        .addFirst(new MapPropertySource("test", properties));
                context.registerBean(io.opentelemetry.api.OpenTelemetry.class, () -> sdk);
                context.register(SslAutoConfiguration.class, SeclumeSslAutoConfiguration.class);
                context.refresh();
                context.getBean(SslBundles.class).getBundle("web");
                assertTrue(context.getBeansOfType(SeclumeCertificateOpenTelemetry.class)
                        .size() == 1);
                io.opentelemetry.sdk.metrics.data.MetricData expiry = reader.collectAllMetrics()
                        .stream().filter(m -> m.getName().equals("seclume.certificate.expiry"))
                        .findFirst().orElseThrow(() -> new AssertionError("no expiry gauge"));
                io.opentelemetry.sdk.metrics.data.DoublePointData point = expiry
                        .getDoubleGaugeData().getPoints().iterator().next();
                assertEquals("web", point.getAttributes().get(
                        io.opentelemetry.api.common.AttributeKey.stringKey("bundle")));
                assertTrue(point.getValue() > 0 && point.getValue() <= 2 * 86400,
                        "expiry " + point.getValue());
            }
        }
    }

    @Test
    void aVaultBundleIsNamedAfterItselfUnlessItNamesItself() {
        SeclumeSslAutoConfiguration.BundleProperties properties =
                new SeclumeSslAutoConfiguration.BundleProperties();
        properties.setVaultPki("address=https://v:8200&pki-role=r&common-name=a");
        assertTrue(SeclumeSslAutoConfiguration.vaultPkiSpec("client", properties)
                .endsWith("&name=client"));
        properties.setVaultPki("address=https://v:8200&name=mine&pki-role=r&common-name=a");
        assertEquals(properties.getVaultPki(),
                SeclumeSslAutoConfiguration.vaultPkiSpec("client", properties));
    }
}
