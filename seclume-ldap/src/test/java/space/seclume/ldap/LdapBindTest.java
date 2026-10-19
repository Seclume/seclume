package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Reference;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.listener.InMemorySASLBindHandler;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ResultCode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.query.LdapQueryBuilder;

import space.seclume.internal.Gssapi;
import space.seclume.tck.NoSecretInHeap;

/** JNDI and Spring LDAP bind over LDAPS and StartTLS, with off-heap simple bind or Kerberos GSSAPI. */
class LdapBindTest {

    private static final byte[] AP_REQ = "mock-krb5-ap-req-token".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AP_REP = "mock-krb5-ap-rep-token".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WRAP_PREFIX = "gss-wrap:".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    static Path directory;

    static LdapServer server;

    @BeforeAll
    static void start() throws Exception {
        server = LdapServer.start(directory);
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.close();
        }
    }

    private static String mailOf(DirContext context, String uid) throws Exception {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> found = context.search("", "(uid=" + uid + ")",
                controls);
        return (String) found.next().getAttributes().get("mail").get();
    }

    /** The bind is a SecretUse event - ldap, simple-bind, the server - and no password. */
    @Test
    void theBindIsRecorded() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        var events = space.seclume.tck.Recorded.during(() -> {
            DirContext context = new InitialDirContext(ldap.environment());
            context.close();
        }, "space.seclume.SecretUse");
        assertEquals(1, events.size(), events.toString());
        assertEquals("ldap", events.get(0).getString("kind"));
        assertEquals("simple-bind", events.get(0).getString("mechanism"));
    }

    @Test
    void jndiBindsAndSearches() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        DirContext context = new InitialDirContext(ldap.environment());
        try {
            assertEquals("alice@example.com", mailOf(context, "alice"));
        } finally {
            context.close();
        }
    }

    @Test
    void jndiBindsAndSearchesOverStartTls() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.startTlsUrl());
        assertTrue(ldap.url().startsWith("ldap://"), ldap.url());
        DirContext context = new InitialDirContext(ldap.environment());
        try {
            assertEquals("alice@example.com", mailOf(context, "alice"));
        } finally {
            context.close();
        }
    }

    @Test
    void springLdapBindsAndSearches() {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        LdapContextSource source = new LdapContextSource();
        source.setUrl(ldap.url());
        source.setBase(ldap.base());
        source.setUserDn(ldap.user());
        source.setPassword(ldap.password());
        source.setBaseEnvironmentProperties(ldap.socketFactory());
        source.afterPropertiesSet();
        List<String> mails = new LdapTemplate(source).search(
                LdapQueryBuilder.query().where("uid").is("alice"),
                (org.springframework.ldap.core.AttributesMapper<String>) attributes ->
                        (String) attributes.get("mail").get());
        assertEquals(List.of("alice@example.com"), mails);
    }

    @Test
    void springLdapBindsAndSearchesOverStartTls() {
        SeclumeLdap ldap = SeclumeLdap.of(server.startTlsUrl());
        LdapContextSource source = new LdapContextSource();
        source.setUrl(ldap.url());
        source.setBase(ldap.base());
        source.setUserDn(ldap.user());
        source.setPassword(ldap.password());
        source.setBaseEnvironmentProperties(ldap.socketFactory());
        source.afterPropertiesSet();
        List<String> mails = new LdapTemplate(source).search(
                LdapQueryBuilder.query().where("uid").is("alice"),
                (org.springframework.ldap.core.AttributesMapper<String>) attributes ->
                        (String) attributes.get("mail").get());
        assertEquals(List.of("alice@example.com"), mails);
    }

    @Test
    void startTlsRefusedByServerIsReported() throws Exception {
        try (ServerSocket fake = new ServerSocket(0)) {
            int fakePort = fake.getLocalPort();
            Thread responder = new Thread(() -> {
                try (Socket client = fake.accept();
                     InputStream in = client.getInputStream();
                     OutputStream out = client.getOutputStream()) {
                    byte[] req = new byte[64];
                    in.read(req);
                    // ExtendedResponse (0x78) with resultCode=53 (unwillingToPerform)
                    byte[] resp = new byte[] {
                            0x30, 0x0c,
                            0x02, 0x01, 0x01,
                            0x78, 0x07,
                            0x0a, 0x01, 53,
                            0x04, 0x00,
                            0x04, 0x00
                    };
                    out.write(resp);
                    out.flush();
                } catch (Exception ignored) {
                }
            });
            responder.setDaemon(true);
            responder.start();

            SeclumeLdap ldap = SeclumeLdap.of("ldap://localhost:" + fakePort + "/" + LdapServer.BASE
                    + "?user=" + LdapServer.SERVICE
                    + "&tlsRootCert=" + server.certificate.toString().replace('\\', '/')
                    + "&provider=file&path=" + server.password.toString().replace('\\', '/'));
            NamingException ex = assertThrows(NamingException.class,
                    () -> new InitialDirContext(ldap.environment()).close());
            assertTrue(fullMessage(ex).contains("StartTLS on localhost:" + fakePort
                    + " was refused by the server (LDAP result 53)"), fullMessage(ex));
        }
    }

    @Test
    void startTlsRejectsPlaintextInjectionAfterResponse() throws Exception {
        try (ServerSocket fake = new ServerSocket(0)) {
            int fakePort = fake.getLocalPort();
            Thread responder = new Thread(() -> {
                try (Socket client = fake.accept();
                     InputStream in = client.getInputStream();
                     OutputStream out = client.getOutputStream()) {
                    byte[] req = new byte[64];
                    in.read(req);
                    // ExtendedResponse (0x78) with resultCode=0, plus injected trailing plaintext byte
                    byte[] respWithInjectedByte = new byte[] {
                            0x30, 0x0c,
                            0x02, 0x01, 0x01,
                            0x78, 0x07,
                            0x0a, 0x01, 0x00,
                            0x04, 0x00,
                            0x04, 0x00,
                            0x30 // injected extra byte before TLS handshake
                    };
                    out.write(respWithInjectedByte);
                    out.flush();
                } catch (Exception ignored) {
                }
            });
            responder.setDaemon(true);
            responder.start();

            SeclumeLdap ldap = SeclumeLdap.of("ldap://localhost:" + fakePort + "/" + LdapServer.BASE
                    + "?user=" + LdapServer.SERVICE
                    + "&tlsRootCert=" + server.certificate.toString().replace('\\', '/')
                    + "&provider=file&path=" + server.password.toString().replace('\\', '/'));
            NamingException ex = assertThrows(NamingException.class,
                    () -> new InitialDirContext(ldap.environment()).close());
            assertTrue(fullMessage(ex).contains("sent bytes after the StartTLS response"),
                    fullMessage(ex));
        }
    }

    @Test
    void kerberosSaslGssapiBindsAndSearchesOverLdapsAndStartTls() throws Exception {
        AtomicReference<String> negotiatedAuthzId = new AtomicReference<>();
        try (InMemoryDirectoryServer ds = startGssapiServer((byte) 0x07, true, negotiatedAuthzId)) {
            int ldapsPort = ds.getListenPort("LDAPS");
            int startTlsPort = ds.getListenPort("STARTTLS");
            String cert = server.certificate.toString().replace('\\', '/');

            // 1. Over LDAPS with authorizationId (user=) and JFR SecretUse verification
            SeclumeLdap ldaps = SeclumeLdap.of("ldaps://localhost:" + ldapsPort + "/"
                    + LdapServer.BASE + "?authentication=kerberos&user=u:svc-app@EXAMPLE.COM"
                    + "&tlsRootCert=" + cert, MockGssContext::new);
            var events = space.seclume.tck.Recorded.during(() -> {
                DirContext ctx = new InitialDirContext(ldaps.environment());
                try {
                    assertEquals("alice@example.com", mailOf(ctx, "alice"));
                } finally {
                    ctx.close();
                }
            }, "space.seclume.SecretUse");
            assertEquals(1, events.size(), events.toString());
            assertEquals("ldap", events.get(0).getString("kind"));
            assertEquals("kerberos-bind", events.get(0).getString("mechanism"));
            assertEquals("u:svc-app@EXAMPLE.COM", negotiatedAuthzId.get());

            // 2. Over StartTLS (ldap://) with Spring LDAP and default empty authorizationId
            SeclumeLdap startTls = SeclumeLdap.of("ldap://localhost:" + startTlsPort + "/"
                    + LdapServer.BASE + "?authentication=gssapi&serviceName=ldap"
                    + "&tlsRootCert=" + cert, MockGssContext::new);
            LdapContextSource source = new LdapContextSource();
            source.setUrl(startTls.url());
            source.setBase(startTls.base());
            source.setUserDn(startTls.user());
            source.setPassword(startTls.password());
            source.setBaseEnvironmentProperties(startTls.socketFactory());
            source.afterPropertiesSet();
            List<String> mails = new LdapTemplate(source).search(
                    LdapQueryBuilder.query().where("uid").is("alice"),
                    (org.springframework.ldap.core.AttributesMapper<String>) attributes ->
                            (String) attributes.get("mail").get());
            assertEquals(List.of("alice@example.com"), mails);
            assertEquals("", negotiatedAuthzId.get());
        }
    }

    @Test
    void kerberosRefusesServerWithoutNoProtectionQop() throws Exception {
        // Server offers only 0x04 (CONFIDENTIALITY), not 0x01 (NO_PROTECTION)
        try (InMemoryDirectoryServer ds = startGssapiServer((byte) 0x04, true, new AtomicReference<>())) {
            int ldapsPort = ds.getListenPort("LDAPS");
            SeclumeLdap ldaps = SeclumeLdap.of("ldaps://localhost:" + ldapsPort + "/"
                    + LdapServer.BASE + "?authentication=kerberos&tlsRootCert="
                    + server.certificate.toString().replace('\\', '/'), MockGssContext::new);
            NamingException ex = assertThrows(NamingException.class,
                    () -> new InitialDirContext(ldaps.environment()).close());
            assertTrue(fullMessage(ex).contains("does not allow SASL GSSAPI NO_PROTECTION over TLS"),
                    fullMessage(ex));
        }
    }

    @Test
    void kerberosRefusesMissingMutualAuthChallenge() throws Exception {
        try (InMemoryDirectoryServer ds = startGssapiServer((byte) 0x07, false, new AtomicReference<>())) {
            int ldapsPort = ds.getListenPort("LDAPS");
            SeclumeLdap ldaps = SeclumeLdap.of("ldaps://localhost:" + ldapsPort + "/"
                    + LdapServer.BASE + "?authentication=kerberos&tlsRootCert="
                    + server.certificate.toString().replace('\\', '/'), MockGssContext::new);
            NamingException ex = assertThrows(NamingException.class,
                    () -> new InitialDirContext(ldaps.environment()).close());
            assertTrue(fullMessage(ex).contains("did not return a Kerberos challenge for mutual authentication"),
                    fullMessage(ex));
        }
    }

    @Test
    void kerberosRealOsStackReportsClearErrorWhenNoKdcOrTicket() {
        SeclumeLdap ldaps = SeclumeLdap.of("ldaps://localhost:" + server.port + "/"
                + LdapServer.BASE + "?authentication=kerberos&serverSpn=ldap/nonexistent.invalid"
                + "&tlsRootCert=" + server.certificate.toString().replace('\\', '/'));
        assertThrows(CommunicationException.class,
                () -> new InitialDirContext(ldaps.environment()).close());
    }

    @Test
    void aWrongPasswordIsRefusedByTheServer() throws Exception {
        Path wrong = directory.resolve("wrong-password");
        Files.writeString(wrong, "not-the-password");
        SeclumeLdap ldap = SeclumeLdap.of(server.url(wrong));
        assertThrows(AuthenticationException.class,
                () -> new InitialDirContext(ldap.environment()).close());
    }

    @Test
    void anEndUserBindsWithWhatTheyTyped() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        Hashtable<String, Object> environment = ldap.environment();
        environment.put(Context.SECURITY_PRINCIPAL, LdapServer.ALICE);
        environment.put(Context.SECURITY_CREDENTIALS, LdapServer.ALICE_PASSWORD);
        new InitialDirContext(environment).close();
    }

    @Test
    void onlyLdapsOrLdapStartTlsAndValidAuthAreTaken() {
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "http://localhost/dc=x?user=cn=a&provider=file&path=/x"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldaps://localhost/dc=x?provider=file&path=/x"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldaps://cn=a:secret@localhost/dc=x?user=cn=a&provider=file&path=/x"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldaps://localhost/dc=x?authentication=digest-md5"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldaps://localhost/dc=x?authentication=kerberos&provider=file&path=/x"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldaps://localhost/dc=x?authentication=kerberos&password=inline"));
    }

    @Test
    void thePasswordIsNotOnTheHeap() throws Exception {
        SeclumeLdap ldaps = SeclumeLdap.of(server.url());
        SeclumeLdap startTls = SeclumeLdap.of(server.startTlsUrl());
        for (int i = 0; i < 3; i++) {
            DirContext context = new InitialDirContext(ldaps.environment());
            mailOf(context, "alice");
            context.close();

            DirContext startTlsContext = new InitialDirContext(startTls.environment());
            mailOf(startTlsContext, "alice");
            startTlsContext.close();
        }
        NoSecretInHeap.assertAbsent(server.password);

        String leaked = Files.readString(server.password); // the control, on the heap on purpose
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(server.password));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }

    private static String fullMessage(Throwable t) {
        StringBuilder sb = new StringBuilder();
        while (t != null) {
            if (t.getMessage() != null) {
                sb.append(t.getMessage()).append(' ');
            }
            t = t.getCause();
        }
        return sb.toString();
    }

    private static InMemoryDirectoryServer startGssapiServer(byte qopMask, boolean sendApRep,
            AtomicReference<String> negotiatedAuthzId) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(directory.resolve("store.p12").toFile())) {
            ks.load(in, "keystore".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "keystore".toCharArray());
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LdapServer.BASE);
        config.setListenerConfigs(
                InMemoryListenerConfig.createLDAPSConfig("LDAPS", null, 0,
                        sslContext.getServerSocketFactory(), null),
                InMemoryListenerConfig.createLDAPConfig("STARTTLS", null, 0,
                        sslContext.getSocketFactory()));
        config.addSASLBindHandler(new InMemorySASLBindHandler() {
            private int step;

            @Override
            public String getSASLMechanismName() {
                return "GSSAPI";
            }

            @Override
            public BindResult processSASLBind(InMemoryRequestHandler handler, int messageID,
                                              DN bindDN, ASN1OctetString credentials,
                                              List<Control> controls) {
                byte[] credBytes = credentials == null ? new byte[0] : credentials.getValue();
                if (Arrays.equals(AP_REQ, credBytes)) {
                    step = 1;
                } else {
                    step++;
                }
                if (step == 1) {
                    assertArrayEquals(AP_REQ, credBytes);
                    if (!sendApRep) {
                        return new BindResult(messageID, ResultCode.SASL_BIND_IN_PROGRESS,
                                null, null, null, null, null);
                    }
                    return new BindResult(messageID, ResultCode.SASL_BIND_IN_PROGRESS,
                            null, null, null, null, new ASN1OctetString(AP_REP));
                } else if (step == 2) {
                    assertEquals(0, credBytes.length);
                    byte[] challenge = new byte[] {qopMask, 0x00, 0x10, 0x00};
                    byte[] wrapped = new byte[WRAP_PREFIX.length + challenge.length];
                    System.arraycopy(WRAP_PREFIX, 0, wrapped, 0, WRAP_PREFIX.length);
                    System.arraycopy(challenge, 0, wrapped, WRAP_PREFIX.length, challenge.length);
                    return new BindResult(messageID, ResultCode.SASL_BIND_IN_PROGRESS,
                            null, null, null, null, new ASN1OctetString(wrapped));
                } else {
                    step = 0;
                    assertTrue(credBytes.length >= WRAP_PREFIX.length + 4);
                    byte[] unwrapped = Arrays.copyOfRange(credBytes, WRAP_PREFIX.length,
                            credBytes.length);
                    assertEquals(0x01, unwrapped[0] & 0xff);
                    negotiatedAuthzId.set(new String(unwrapped, 4, unwrapped.length - 4,
                            StandardCharsets.UTF_8));
                    return new BindResult(messageID, ResultCode.SUCCESS, null, null, null, null, null);
                }
            }
        });
        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
        ds.importFromLDIF(true, directory.resolve("data.ldif").toFile());
        ds.startListening();
        return ds;
    }

    private static final class MockGssContext implements Gssapi.Context {
        private boolean complete;

        @Override
        public byte[] step(MemorySegment serverToken, long offset, int length) {
            if (serverToken == null) {
                return AP_REQ.clone();
            }
            byte[] received = new byte[length];
            MemorySegment.copy(serverToken, ValueLayout.JAVA_BYTE, offset, received, 0, length);
            assertArrayEquals(AP_REP, received);
            complete = true;
            return new byte[0];
        }

        @Override
        public boolean complete() {
            return complete;
        }

        @Override
        public byte[] unwrap(byte[] token) {
            assertTrue(token.length >= WRAP_PREFIX.length);
            return Arrays.copyOfRange(token, WRAP_PREFIX.length, token.length);
        }

        @Override
        public byte[] wrap(byte[] payload) {
            byte[] out = new byte[WRAP_PREFIX.length + payload.length];
            System.arraycopy(WRAP_PREFIX, 0, out, 0, WRAP_PREFIX.length);
            System.arraycopy(payload, 0, out, WRAP_PREFIX.length, payload.length);
            return out;
        }

        @Override
        public void close() {
        }
    }
}
