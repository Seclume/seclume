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
