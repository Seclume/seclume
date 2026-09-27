package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.integration.sftp.session.DefaultSftpSessionFactory;
import org.springframework.ldap.core.support.LdapContextSource;

import com.sun.net.httpserver.HttpServer;

import io.awspring.cloud.autoconfigure.AwsAsyncClientCustomizer;
import io.awspring.cloud.autoconfigure.AwsSyncClientCustomizer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;

import space.seclume.crypto.OpenSslSigningKey;

/** AWS, LDAP and SSH from application.properties. */
class IntegrationsAutoConfigurationTest {

    @TempDir
    Path directory;

    private static AnnotationConfigApplicationContext context(Class<?> configuration,
                                                              String... pairs) {
        Map<String, Object> properties = new HashMap<>();
        for (String pair : pairs) {
            properties.put(pair.substring(0, pair.indexOf('=')),
                    pair.substring(pair.indexOf('=') + 1));
        }
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(configuration);
        context.refresh();
        return context;
    }

    @Test
    void awsClientsSignWithTheKeyFromItsProvider() throws Exception {
        Path key = directory.resolve("aws-key");
        Files.writeString(key, "an-aws-secret-key-for-this-test");
        List<String> authorizations = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            authorizations.add(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.start();
        try (AnnotationConfigApplicationContext context = context(
                SeclumeAwsAutoConfiguration.class, "seclume.aws.access-key-id=AKIATEST",
                "seclume.aws.region=eu-central-1",
                "seclume.aws.secret-access-key=provider=file&path=" + key)) {
            assertEquals(1, context.getBeansOfType(AwsAsyncClientCustomizer.class).size());
            S3ClientBuilder builder = S3Client.builder().region(Region.US_EAST_1)
                    .endpointOverride(URI.create("http://127.0.0.1:"
                            + server.getAddress().getPort())).forcePathStyle(true);
            context.getBean(AwsSyncClientCustomizer.class).customize(builder);
            try (S3Client s3 = builder.build()) {
                s3.putObject(b -> b.bucket("b").key("k"), RequestBody.fromString("v"));
            }
            assertEquals(1, authorizations.size());
            assertTrue(authorizations.get(0).startsWith("AWS4-HMAC-SHA256 Credential=AKIATEST/"
                    + java.time.LocalDate.now(java.time.ZoneOffset.UTC).format(
                            java.time.format.DateTimeFormatter.BASIC_ISO_DATE)
                    + "/eu-central-1/s3/"), authorizations.get(0));
        } finally {
            server.stop(0);
        }
        assertThrows(Exception.class, () -> context(SeclumeAwsAutoConfiguration.class,
                "seclume.aws.access-key-id=AKIATEST",
                "seclume.aws.secret-access-key=the-key-itself").close());
    }

    @Test
    void ldapContextSourceFromTheUrl() throws Exception {
        Path password = directory.resolve("ldap");
        Files.writeString(password, "an-ldap-password");
        try (AnnotationConfigApplicationContext context = context(
                SeclumeLdapAutoConfiguration.class, "seclume.ldap.url=ldaps://ad.example.com/"
                        + "dc=example,dc=com?user=svc@example.com&provider=file&path=" + password)) {
            LdapContextSource source = context.getBean(LdapContextSource.class);
            assertEquals("ldaps://ad.example.com:636", source.getUrls()[0]);
            assertEquals("dc=example,dc=com", source.getBaseLdapPathAsString());
            assertEquals("svc@example.com", source.getUserDn());
            assertTrue(source.getPassword().startsWith("seclume-ldap-binds-in-native-memory:"));
        }
    }

    @Test
    void sshClientAndSftpSessionFactory() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        Path script = directory.resolve("key.sh");
        Files.writeString(script, "cd '" + directory + "' && openssl genpkey -algorithm EC "
                + "-pkeyopt ec_paramgen_curve:P-256 -out id_ecdsa 2>/dev/null\n");
        Process process = new ProcessBuilder("/bin/sh", script.toString()).start();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0);
        try (AnnotationConfigApplicationContext context = context(
                SeclumeSshAutoConfiguration.class,
                "seclume.ssh.key=provider=file&path=" + directory.resolve("id_ecdsa"),
                "seclume.sftp.host=files.example.com", "seclume.sftp.user=deploy")) {
            SshClient client = context.getBean(SshClient.class);
            assertTrue(client.isStarted());
            KeyPair pair = client.getKeyIdentityProvider().loadKeys(null).iterator().next();
            assertEquals("space.seclume.keys.OpenSslPrivateKey$Ec",
                    pair.getPrivate().getClass().getName());
            context.getBean(DefaultSftpSessionFactory.class);
        }
    }
}
