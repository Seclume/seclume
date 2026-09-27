package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Path;
import java.util.HashMap;
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
        Process process = new ProcessBuilder("sh", "-c", "cd '" + directory + "' && "
                + "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem"
                + " && openssl req -x509 -new -key key.pem -out cert.pem -days 2"
                + " -subj /CN=localhost -addext subjectAltName=DNS:localhost")
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
}
